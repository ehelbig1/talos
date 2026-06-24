// MCP-952 (2026-05-15): kept `#![allow(dead_code)]` deliberately.
// The worker binary carries several pre-existing dead items that
// span multiple modules (signing/verify_signature methods,
// get_state, cancellation_token field, take_stderr_output and
// memory-key helpers, try_deduct_crypto_budget/cancel, is_mutation,
// etc.). Each is non-trivial to audit individually — they could
// be vestigial post-refactor surface, conditional-build hooks,
// or wiring awaiting a real consumer. A clean removal would
// need surgical review per item against the worker's WIT host
// function set and the broader signing protocol; that's not a
// drive-by sweep target. Vestigial-retention class (see MCP-946).
#![allow(dead_code)]
//! Talos Worker - WASM Execution Engine
//!
//! Production-grade worker with:
//! - OpenTelemetry metrics (Prometheus)
//! - Distributed tracing (Jaeger)
//! - Health checks
//! - Graceful shutdown
//! - NATS-based job queue
//! - HMAC-signed job verification
//! - AES-256-GCM encrypted secrets in transit

use crate::runtime::{PipelineStepSpec, RetryPolicy, SecurityPolicy};
use async_nats::Client;
use async_nats::Subscriber;
use futures_util::stream::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use talos_workflow_job_protocol::{
    load_worker_key_ring, JobRequest, JobResult, JobStatus, PipelineJobRequest, PipelineJobResult,
    PipelineStepResult,
};

mod audit;
mod bindings;
mod circuit_breaker;
mod context;
mod expose_fallback;
mod host_impl;
mod job_idempotency;
mod metrics;
mod metrics_server;
mod runtime;
mod s3_signer;
mod sql_validator;
mod ssrf_resolver;
mod trace_nats;
mod tracing;
mod wit_inspector;
mod worker_identity;

use crate::runtime::TalosRuntime;

/// Maximum concurrent single-node job executions
const MAX_CONCURRENT_JOBS: usize = 100;
/// Maximum concurrent pipeline job executions (heavier — multi-step)
const MAX_CONCURRENT_PIPELINE_JOBS: usize = 20;
/// Redis TTL for cached OCI layer pulls. 24h covers daily mutable-tag refresh
/// while bounding cache growth — without a TTL, distinct module URIs (every
/// new tag) accumulate forever. Digest-pinned URIs re-cache identical bytes
/// on every miss, so the TTL is harmless there.
const OCI_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// H-3: Maximum decompressed OCI layer size the worker will accept.
///
/// `oci_distribution::Client::pull` buffers each layer into a
/// `Vec<u8>` AFTER gzip decompression. Without a cap, a hostile or
/// compromised registry can serve a small gzipped layer that
/// decompresses to many gigabytes and OOMs the worker (the pooling
/// allocator's 128 MiB per-instance bound only protects memory
/// inside wasmtime, not host-side `Vec` allocations).
///
/// M-1 (2026-05-22): tightened from 64 MiB → 32 MiB. The largest
/// templates in the catalog are < 8 MiB AOT-compiled, < 1 MiB
/// uncompiled, so 32 MiB is still ~4× headroom over realistic
/// traffic. The pre-pull manifest check filters typical attacks
/// using the manifest-declared (compressed) size, but a registry
/// that lies about layer size — or serves a properly-signed
/// compression-bomb payload (compressed << decompressed) — can
/// drive the host allocator past the cap before the post-pull
/// `data.len()` check at the call site sees it. Lowering the
/// default ceiling reduces the OOM blast radius without affecting
/// legitimate templates. Operators with bespoke large modules
/// raise via `WORKER_MAX_OCI_LAYER_BYTES`; defense-in-depth
/// check at both pre-pull (manifest's declared size) and
/// post-pull (actual `data.len()`).
const DEFAULT_MAX_OCI_LAYER_BYTES: u64 = 32 * 1024 * 1024;

/// Env-configurable override for [`DEFAULT_MAX_OCI_LAYER_BYTES`].
/// `0` / unset / malformed → use the default. Loaded lazily on
/// first OCI pull (cheap; not a hot path).
fn max_oci_layer_bytes() -> u64 {
    std::env::var("WORKER_MAX_OCI_LAYER_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_OCI_LAYER_BYTES)
}

/// Decision returned by [`check_manifest_layer_sizes`] — keeps the
/// security-critical policy testable in isolation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ManifestSizeVerdict {
    /// All declared layer sizes are within bounds.
    Ok,
    /// At least one layer's declared `size` exceeds the cap. Carries
    /// both the offending declared size and the cap for log lines.
    Oversized { declared: i64, cap: u64 },
}

/// Pre-pull check: refuse to fetch an OCI artifact whose manifest
/// declares any layer larger than `cap`. Pure function so the policy
/// is unit-testable without a registry. Negative `size` values (the
/// manifest spec allows i64 but values < 0 are nonsense) are treated
/// as oversized so a forged manifest can't bypass the gate by claiming
/// a negative size.
pub(crate) fn check_manifest_layer_sizes(layer_sizes: &[i64], cap: u64) -> ManifestSizeVerdict {
    for &size in layer_sizes {
        if size < 0 || (size as u64) > cap {
            return ManifestSizeVerdict::Oversized {
                declared: size,
                cap,
            };
        }
    }
    ManifestSizeVerdict::Ok
}

/// Sigstore enforcement modes for OCI artifact signature verification.
/// Resolved once at process startup from `TALOS_SIGSTORE_REQUIRED`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SigstorePolicy {
    /// Don't verify signatures. Right for dev/local where the worker can't
    /// reach Fulcio/Rekor and templates aren't signed. The default.
    Disabled,
    /// Try to verify; on failure log a warning but continue. Right for the
    /// migration window when some templates are signed and some aren't.
    Audit,
    /// Verify is mandatory; failure => refuse to execute. Production setting.
    Required,
}

impl SigstorePolicy {
    /// Parse the operator's `TALOS_SIGSTORE_REQUIRED` env var into a policy.
    ///
    /// Recognised values:
    ///   * `required` / `true` / `1` → `Required`
    ///   * `audit` / `warn`          → `Audit`
    ///   * `disabled` / `off` / `0`  → `Disabled` (explicit opt-out)
    ///   * unset / empty / anything else → `Disabled` (silent default)
    ///
    /// **The silent-default branch is policed by [`enforce_production_policy_explicit`]**.
    /// In production we refuse to boot unless the operator has explicitly
    /// chosen one of the recognised values — the silent fallthrough is a
    /// deployment trap we caught in the 2026-05-22 wasm-security review
    /// (MEDIUM-4): an operator who forgot to set the env var got Sigstore
    /// silently disabled with no startup warning, defeating the entire
    /// signature-verification chain. The pure parse here stays minimal and
    /// fail-safe (unknown → Disabled, never up-grading to a stricter policy);
    /// the production-gate lives at the boot path so dev/test environments
    /// keep the lenient default.
    fn from_env() -> Self {
        Self::from_env_str(&std::env::var("TALOS_SIGSTORE_REQUIRED").unwrap_or_default())
    }

    /// Pure parse helper. Split out so unit tests don't touch process env.
    fn from_env_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "required" => Self::Required,
            "audit" | "warn" => Self::Audit,
            // Explicit opt-out aliases. Operators who *want* Disabled in
            // production set one of these so the production gate below
            // sees an explicit choice instead of silent emptiness.
            "disabled" | "off" | "0" | "false" | "no" => Self::Disabled,
            // Anything else (including empty) → Disabled, but the
            // production gate refuses to boot in this state. Tests on
            // dev hosts continue to see the silent default.
            _ => Self::Disabled,
        }
    }

    /// Was the operator explicit about the Sigstore policy?
    ///
    /// Distinguishes "operator set `TALOS_SIGSTORE_REQUIRED=disabled`,
    /// accepting the risk" from "operator forgot to set anything". The
    /// production gate refuses to boot in the second state.
    fn raw_env_is_explicit(raw: &str) -> bool {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "true"
                | "1"
                | "required"
                | "audit"
                | "warn"
                | "disabled"
                | "off"
                | "0"
                | "false"
                | "no"
        )
    }
}

/// Production-only gate: refuse to boot when the operator hasn't made an
/// explicit Sigstore choice.
///
/// Mirrors the `TALOS_AOT_HMAC_KEY` startup discipline at
/// [`runtime::aot_key_ring`]: in production, fail loud at boot rather than
/// devolving to a "silent unverified" posture that looks identical to
/// "verification ran and passed" from the operator's monitoring.
///
/// Returns `Ok(policy)` in three cases:
///   1. We're not in production (dev/test) — the silent default is fine.
///   2. Operator set an explicit recognised value — any of them is fine,
///      including `disabled`, because operator chose it knowingly.
///   3. Operator set `audit` or `required` — fine by definition.
///
/// Returns `Err` in production when the env var is unset / empty / set to
/// an unrecognised value — the operator's intent is ambiguous, refuse to
/// guess.
fn enforce_production_sigstore_policy_explicit() -> anyhow::Result<SigstorePolicy> {
    let raw = std::env::var("TALOS_SIGSTORE_REQUIRED").unwrap_or_default();
    let policy = SigstorePolicy::from_env_str(&raw);

    if !talos_config::is_production() {
        return Ok(policy);
    }

    if SigstorePolicy::raw_env_is_explicit(&raw) {
        return Ok(policy);
    }

    Err(anyhow::anyhow!(
        "CRITICAL: TALOS_SIGSTORE_REQUIRED must be set explicitly in production. \
         Set to `required` for fail-closed signature verification (recommended), \
         `audit` for warn-and-continue during a migration window, or `disabled` \
         to explicitly accept the security risk of running unsigned WASM artifacts. \
         Refusing to boot rather than silently devolving to no-verification — \
         see worker/src/main.rs::SigstorePolicy for rationale."
    ))
}

/// Reasons a Sigstore identity regexp is too permissive to enforce.
/// Returned by [`validate_sigstore_identity_regexp`] so the worker can
/// fail closed at startup instead of accepting a setting that defeats
/// the entire signature-verification chain. Pure data so it's easy to
/// match on / test.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SigstoreRegexpRejection {
    /// The string is empty — the caller should treat this as
    /// "explicitly not configured" rather than a parse error, but in
    /// `Required` mode it's still a hard failure (see callsite).
    Empty,
    /// One of the known catch-all patterns: `.*`, `.+`, `.`, `^.*$`,
    /// etc. A regex this broad accepts any Fulcio cert identity, which
    /// is the same as having no verification at all.
    TooBroad,
    /// The pattern doesn't compile as a regex. Fail closed early so
    /// `cosign verify` doesn't error in production with an opaque
    /// upstream message.
    InvalidRegex,
    /// The pattern would match a GitHub repo or workflow URL prefix
    /// without ever anchoring the trailing `@` separator. Per the
    /// CLAUDE.md guidance: without the `@`, an attacker who creates a
    /// fork named `template-publish.yml-evil.yml` can match the same
    /// prefix.
    MissingWorkflowAnchor,
    /// L-14 (2026-05-22): the pattern starts with `https://github.com/`
    /// (the GitHub-Actions Fulcio identity prefix) but does not contain
    /// `.github/workflows/`. Sigstore identities for GitHub Actions
    /// OIDC ALWAYS include the workflow path — a pattern like
    /// `^https://github\.com/.*` would match every signed artifact from
    /// every owner/repo on github.com, defeating the per-workflow
    /// trust anchor.
    MissingGithubWorkflowPath,
    /// L-14: the pattern contains `github.com/.*\.github/workflows/`
    /// or similar wildcard between `github.com/` and the workflow
    /// path. This expands the trust set to any owner/repo with a
    /// matching workflow filename — including a forked repo with the
    /// same filename. Pin the owner/repo literally.
    UnpinnedGithubOwnerRepo,
    /// Pattern starts with `https://` but is missing the `^` start-of-string
    /// anchor. Cosign uses `regex::Regex::is_match` semantics — a missing
    /// `^` means the literal `https://...` could appear anywhere inside
    /// the SAN URI. While GitHub Actions OIDC SANs are well-structured,
    /// a `^` anchor is cheap defense in depth (and matches the
    /// documented operator examples in this file's human_reason() text).
    /// Wasm-security review 2026-05-23.
    MissingStartAnchor,
}

impl SigstoreRegexpRejection {
    pub(crate) fn human_reason(&self) -> &'static str {
        match self {
            Self::Empty => "TALOS_SIGSTORE_IDENTITY_REGEXP is empty",
            Self::TooBroad => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP matches anything — pin it to your \
                 workflow URL pattern (e.g. \
                 `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`)"
            }
            Self::InvalidRegex => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP is not a valid regex — `cosign verify` will reject every artifact"
            }
            Self::MissingWorkflowAnchor => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP looks like a GitHub workflow pattern \
                 but is missing the trailing `@` anchor — a fork named \
                 `workflow.yml-evil.yml` could match the same prefix. \
                 End the pattern with `@` to anchor at the ref separator."
            }
            Self::MissingGithubWorkflowPath => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP targets `github.com` but does not \
                 require the `.github/workflows/` path — every Sigstore identity \
                 issued by GitHub Actions OIDC contains that path, so a pattern \
                 without it would match unrelated artifacts from any owner/repo. \
                 Use a pattern like \
                 `^https://github\\.com/OWNER/REPO/\\.github/workflows/WORKFLOW\\.yml@`."
            }
            Self::UnpinnedGithubOwnerRepo => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP has a wildcard between `github.com/` \
                 and `.github/workflows/` — owner and repo MUST be literal so a \
                 fork with the same workflow filename can't satisfy the regex. \
                 Replace `github\\.com/.*` with `github\\.com/OWNER/REPO/`."
            }
            Self::MissingStartAnchor => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP starts with `https://` but is \
                 missing the `^` start-of-string anchor. Add `^` at the front \
                 (e.g. `^https://github\\.com/OWNER/REPO/...`)."
            }
        }
    }
}

/// Validate `regexp` for use as `--certificate-identity-regexp` in
/// `cosign verify`. Pure function so the security policy is easy to
/// test and cannot drift between callsites. Returns `Ok(())` if the
/// pattern is acceptable; `Err(reason)` otherwise.
///
/// Policy:
/// 1. Empty string is rejected (callers may special-case Empty for
///    `Disabled` policy mode, but the underlying check stays the
///    same).
/// 2. Known catch-all patterns are rejected. Treating `.*` /
///    `.+` / `.` / `^.*$` / `^.+$` as too broad covers the most
///    common foot-gun — an operator who sets the regexp to "any"
///    while leaving `TALOS_SIGSTORE_REQUIRED=true` would silently
///    defeat verification.
/// 3. The pattern must compile as a regex.
/// 4. Patterns targeting `github.com/.../.github/workflows/...`
///    MUST end with `@` (per the workflow-URL anchor convention
///    documented in CLAUDE.md). Missing this trailing `@` is
///    spoofable via a fork repo named `workflow.yml-evil.yml`.
pub(crate) fn validate_sigstore_identity_regexp(
    regexp: &str,
) -> Result<(), SigstoreRegexpRejection> {
    if regexp.is_empty() {
        return Err(SigstoreRegexpRejection::Empty);
    }
    // Reject known catch-all patterns. Trim whitespace first so a
    // pasted env-var with stray spaces still triggers the check.
    let trimmed = regexp.trim();
    matches!(
        trimmed,
        ".*" | ".+" | "." | "^.*$" | "^.+$" | "^.$" | "^.*" | ".*$"
    )
    .then(|| Err::<(), _>(SigstoreRegexpRejection::TooBroad))
    .transpose()?;
    // The pattern must compile or `cosign` will reject every artifact.
    if regex::Regex::new(regexp).is_err() {
        return Err(SigstoreRegexpRejection::InvalidRegex);
    }
    // Wasm-security review 2026-05-23: a `https://`-prefixed pattern
    // without a leading `^` matches the URI substring anywhere — cheap
    // defense-in-depth to require the start-anchor that all the doc
    // examples already use. We don't require `^` on non-URL patterns
    // because there are legitimate non-anchored uses (e.g. SAN-email
    // patterns).
    if regexp.starts_with("https://") {
        return Err(SigstoreRegexpRejection::MissingStartAnchor);
    }
    // Workflow-URL convention: if the pattern mentions
    // `.github/workflows/`, the file extension `.yml` (or `.yaml`)
    // must be immediately followed by `@` so the ref separator is
    // anchored. Without it, a fork repo named
    // `workflow.yml-evil.yml` would match the same prefix.
    //
    // The check looks for the `@` to appear AFTER `workflows/` in the
    // pattern source. Both the "ends with @" form (e.g.
    // `…template-publish\.yml@`) and the ref-pinned form (e.g.
    // `…template-publish\.yml@refs/heads/main$`) satisfy it.
    if let Some(workflows_idx) = regexp.find(".github/workflows/") {
        // Slice past the `workflows/` literal so any preceding `@`
        // (would be unusual but harmless) doesn't accidentally
        // satisfy the check.
        let after_workflows = &regexp[workflows_idx + ".github/workflows/".len()..];
        if !after_workflows.contains('@') {
            return Err(SigstoreRegexpRejection::MissingWorkflowAnchor);
        }
    }
    // L-14 (2026-05-22): additional anchoring checks for github.com
    // patterns. Sigstore identities issued by GitHub Actions OIDC
    // always have the form
    // `https://github.com/{owner}/{repo}/.github/workflows/{file}.yml@{ref}`.
    // A pattern that targets github.com but is missing either the
    // `.github/workflows/` path or pins the owner/repo with a
    // wildcard would expand the trust set far beyond the operator's
    // intent (any fork with the same workflow name signs as us).
    //
    // We match both `github\.com/` (regex-escaped) and `github.com/`
    // (raw) since operators write the pattern either way.
    let github_idx = regexp
        .find("github\\.com/")
        .map(|i| (i, "github\\.com/".len()))
        .or_else(|| regexp.find("github.com/").map(|i| (i, "github.com/".len())));
    if let Some((idx, prefix_len)) = github_idx {
        // 1. Pattern must reference a workflow path. Without it, every
        //    OIDC identity from any GitHub repo would satisfy the
        //    regex (e.g. `^https://github\.com/.*`).
        if !regexp.contains(".github/workflows/") {
            return Err(SigstoreRegexpRejection::MissingGithubWorkflowPath);
        }
        // 2. Owner/repo segment between `github.com/` and
        //    `.github/workflows/` must be literal — no wildcards.
        //    `.` (any-char), `.*`, `.+`, `\w+`, `[^/]+`, `\S+`
        //    between the two anchors all defeat per-repo pinning.
        let after_host = &regexp[idx + prefix_len..];
        if let Some(workflows_at) = after_host.find(".github/workflows/") {
            let owner_repo_segment = &after_host[..workflows_at];
            // Bare `.` is the canonical wildcard; `.*` / `.+` / `[]`
            // / `\w` likewise. Backslash-escaped `\.` is a literal
            // dot in the repo name (e.g. `my.repo`) and is fine, so
            // we strip those before scanning. Same for `\-`.
            let scan = owner_repo_segment
                .replace("\\.", "")
                .replace("\\-", "")
                .replace("\\_", "");
            // Any of these tokens between host and workflows path
            // indicates a wildcard.
            let suspicious_tokens = [".*", ".+", "[^", "\\w", "\\S", "\\d", "(?", ".{", "()"];
            if suspicious_tokens.iter().any(|t| scan.contains(t)) {
                return Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo);
            }
            // A bare `.` (any-character) outside an escape is also
            // suspicious. Scan for it in the post-strip text.
            if scan.contains('.') {
                return Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo);
            }
        }
    }
    Ok(())
}

/// Build the `cosign verify` argv for a given OCI reference. Pure
/// (no env reads, no I/O) so the security-critical command construction
/// is unit-tested without invoking cosign.
///
/// Cert identity + OIDC issuer come from configuration:
/// - `identity_regexp`: regex matched against the SAN URI of the Fulcio
///   cert. Pin to the workflow URL pattern, e.g.
///   `^https://github\.com/OWNER/talos/\.github/workflows/template-publish\.yml@`
/// - `oidc_issuer`: GitHub Actions = `https://token.actions.githubusercontent.com`
pub(crate) fn cosign_verify_argv(
    reference: &str,
    identity_regexp: &str,
    oidc_issuer: &str,
) -> Vec<String> {
    vec![
        "verify".to_string(),
        "--certificate-identity-regexp".to_string(),
        identity_regexp.to_string(),
        "--certificate-oidc-issuer".to_string(),
        oidc_issuer.to_string(),
        // Output to stderr keeps stdout free for structured signal — we don't
        // currently parse stdout, but reserving the channel makes future
        // "extract Rekor entry ID" upgrades non-breaking.
        "--output".to_string(),
        "json".to_string(),
        reference.to_string(),
    ]
}

/// Run `cosign verify` against an OCI reference. Returns `Ok(())` if the
/// signature is valid AND the cert identity / OIDC issuer match. Errors
/// carry a sanitised message safe to surface in JobResult; the unsanitised
/// reason is on tracing::warn for operators.
pub(crate) async fn verify_oci_signature(
    reference: &str,
    identity_regexp: &str,
    oidc_issuer: &str,
) -> Result<(), String> {
    let argv = cosign_verify_argv(reference, identity_regexp, oidc_issuer);
    // Prefer the absolute path pinned at startup so this invocation
    // targets the SAME binary that the M5 `TALOS_COSIGN_SHA256` gate
    // just hashed. When unpinned (tests, audit-mode without a hash
    // pin, pre-startup), fall back to PATH lookup — the operator-
    // visible warning at startup already covers that posture.
    //
    // M (2026-05-23, wasm-security review): in production, refuse the
    // PATH-lookup fallback. A successful M5 hash check at startup that
    // failed to set the OnceLock would silently degrade every
    // subsequent verification — operator-visible warning at boot is
    // not sufficient guarantee that the production verification path
    // uses the hashed binary. Fail-closed here makes the binary-pin
    // invariant hold for every call, not just the happy path.
    let mut command = match cosign_pinned_path() {
        Some(path) => tokio::process::Command::new(path),
        None => {
            if talos_config::is_production() {
                ::tracing::error!(
                    reference = %reference,
                    "SECURITY: cosign binary path was not pinned at startup; \
                     refusing to fall back to PATH lookup in production. The \
                     M5 TALOS_COSIGN_SHA256 hash check requires the same \
                     binary across boot-time hashing and per-call execution. \
                     Confirm cosign is on PATH at worker boot."
                );
                return Err("cosign_unpinned".to_string());
            }
            ::tracing::warn!(
                reference = %reference,
                "cosign path not pinned (dev mode) — falling back to PATH lookup"
            );
            tokio::process::Command::new("cosign")
        }
    };
    let output = match command.args(&argv).output().await {
        Ok(o) => o,
        Err(e) => {
            // ENOENT (cosign missing) is operator misconfig — surface it
            // distinctly so it isn't mistaken for a verification failure.
            ::tracing::error!(
                error = %e,
                "cosign binary not found or unexecutable — install cosign in the worker image"
            );
            return Err("cosign_unavailable".to_string());
        }
    };
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    ::tracing::warn!(
        reference = %reference,
        exit_code = output.status.code().unwrap_or(-1),
        stderr = %stderr,
        "cosign verify failed"
    );
    Err("signature_verification_failed".to_string())
}

/// Parse a `MAJOR.MINOR.PATCH` semver triple out of an arbitrary string.
/// Pure function so the M5 cosign-version-pin policy is unit-testable.
/// Returns `None` when no dotted triple of integers is found. The first
/// triple encountered wins — cosign's `version` output puts the binary's
/// own version on a line preceded by `GitVersion:` or the bare semver,
/// and we don't want to over-fit on the exact format because it has
/// shifted across cosign releases.
pub(crate) fn parse_cosign_version(stdout: &str) -> Option<(u32, u32, u32)> {
    // Scan for any token shaped like `vX.Y.Z` or `X.Y.Z` (with an
    // optional `-suffix` we ignore).
    for token in stdout.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if let Some(triple) = parse_semver_triple(token) {
            return Some(triple);
        }
    }
    None
}

/// Parse a strict `MAJOR.MINOR.PATCH` triple. Pure; companion to
/// `parse_cosign_version`.
pub(crate) fn parse_semver_triple(s: &str) -> Option<(u32, u32, u32)> {
    let trimmed = s.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let maj: u32 = parts.next()?.parse().ok()?;
    let min: u32 = parts.next()?.parse().ok()?;
    // PATCH may carry a `-suffix`; truncate at the first non-digit.
    let patch_raw = parts.next()?;
    let patch_str: String = patch_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if patch_str.is_empty() {
        return None;
    }
    let patch: u32 = patch_str.parse().ok()?;
    Some((maj, min, patch))
}

/// Process-wide pinned absolute path to the `cosign` binary, resolved
/// once at startup and reused for every verification call.
///
/// L-3 follow-up: every `tokio::process::Command::new("cosign")` re-walks
/// `PATH`, so the M5 `TALOS_COSIGN_SHA256` startup check (which hashes the
/// binary at the path returned by `which cosign` at boot) could be
/// circumvented by a later `PATH` mutation — the verify call would resolve
/// a different binary than the one that was hashed. Pinning the absolute
/// path at startup and reusing it makes the M5 hash check apply to every
/// subsequent invocation. Defense-in-depth in the immutable-container
/// happy path; correctness in any environment where `PATH` is mutable.
static COSIGN_BINARY_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Read the pinned cosign path if startup resolution succeeded. Callers
/// in `verify_oci_signature` use this; when `None` (e.g. tests or a
/// pre-startup call), fall back to invoking `cosign` by name — the
/// behavioural difference is only the loss of the PATH-pin guarantee.
pub(crate) fn cosign_pinned_path() -> Option<&'static std::path::Path> {
    COSIGN_BINARY_PATH.get().map(|p| p.as_path())
}

/// Resolve the `cosign` binary on PATH, pin its absolute path for the
/// process lifetime, and compute its SHA-256.
///
/// The path pin is set as a side-effect of a successful resolve so the
/// M5 hash pin gate at startup and the per-invocation execution path
/// agree on which binary is being checked.
async fn resolve_and_hash_cosign_binary() -> anyhow::Result<String> {
    let output = tokio::process::Command::new("which")
        .arg("cosign")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to invoke `which cosign`: {e}"))?;
    if !output.status.success() {
        anyhow::bail!("`which cosign` exited non-zero — binary not on PATH");
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        anyhow::bail!("`which cosign` produced empty output");
    }
    let path_buf = std::path::PathBuf::from(&path);
    let bytes = tokio::fs::read(&path_buf)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read cosign at {path}: {e}"))?;
    use sha2::Digest as _;
    let hash = format!("{:x}", sha2::Sha256::digest(&bytes));
    // Pin the resolved absolute path for the process lifetime so every
    // `verify_oci_signature` invocation targets the same binary the M5
    // startup gate just hashed. `set` is idempotent on success — a later
    // resolve (e.g. in a test) is silently ignored.
    let _ = COSIGN_BINARY_PATH.set(path_buf);
    Ok(hash)
}

/// Decision returned by `verify_oci_layer` — small enum to make the security-
/// critical "should we trust these bytes?" decision testable in isolation.
#[derive(Debug, PartialEq)]
pub(crate) enum LayerVerdict<'a> {
    /// Manifest declared a digest and the layer's recomputed sha256 matches.
    /// Safe to execute and cache.
    Verified { digest: &'a str },
    /// Manifest had no layer descriptor — registry returned a malformed
    /// manifest. Accept with a warning (legacy behaviour) but flag it.
    AcceptedUnverified,
    /// Manifest digest != recomputed digest. Refuse to execute. Returned
    /// with both digests so the caller can log structured fields.
    DigestMismatch { expected: &'a str, computed: String },
}

/// Verify a pulled OCI layer's bytes against its manifest digest. Pure
/// function — no I/O, no allocations beyond the sha256 itself — so it can be
/// unit-tested without a registry. Called from the worker's OCI fetch path
/// before the bytes are cached or executed.
///
/// L-2 (2026-05-22): comparison is constant-time via
/// `subtle::ConstantTimeEq`. Neither input is secret here (manifest digest
/// is public; the computed digest is recomputable from public bytes), so
/// the timing-leak threat model doesn't strictly apply — but keeping the
/// comparison constant-time matches the rest of the workspace's
/// crypto-equality discipline (`talos_memory::rpc_auth`, AOT HMAC,
/// `TALOS_COSIGN_SHA256`) and removes a sharp edge if this code is ever
/// pasted into a key-dependent path.
pub(crate) fn verify_oci_layer<'a>(
    layer_data: &[u8],
    manifest_digest: Option<&'a str>,
) -> LayerVerdict<'a> {
    use sha2::Digest as _;
    use subtle::ConstantTimeEq as _;
    let computed = format!("sha256:{:x}", sha2::Sha256::digest(layer_data));
    match manifest_digest {
        Some(expected) => {
            let eq: bool = expected.as_bytes().ct_eq(computed.as_bytes()).into();
            if eq {
                LayerVerdict::Verified { digest: expected }
            } else {
                LayerVerdict::DigestMismatch { expected, computed }
            }
        }
        None => LayerVerdict::AcceptedUnverified,
    }
}

// ============================================================================
// SECURITY: Static regex compilation — compiled exactly once at first use.
// Recompiling regexes on every call wastes CPU and can cause latency spikes.
// ============================================================================

static RE_UNIX_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_WIN_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_LINE_NUM: OnceLock<regex::Regex> = OnceLock::new();
static RE_INTERNAL_IP: OnceLock<regex::Regex> = OnceLock::new();

// MCP-913 (2026-05-14): bare OnceLock<Client>, no outer Mutex.
// `oci_distribution::Client::pull` takes `&self` (verified against
// the 0.11 source — internal `auth_store: Arc<RwLock<HashMap<...>>>`
// handles the token cache concurrency). Pre-fix `OnceLock<Mutex<Client>>`
// + `client_mutex.lock().await` SERIALIZED every concurrent OCI pull
// through one lock. The critical section held across:
//   - sigstore `cosign verify` subprocess (network + fork, ~1-3s)
//   - OCI registry pull (network + blob transfer, ~1-10s)
//   - layer digest verify (fast)
//   - Redis cache SET (network, fast)
// So under worker concurrency, a second module pull waited for the
// first to FULLY complete the chain. With 5–15s per pull, this
// capped worker module-load throughput at one-at-a-time per scheme
// (HTTPS / HTTP separately). The two schemes don't share locks but
// neither do they handle hostname-level isolation.
static OCI_CLIENT_HTTPS: OnceLock<oci_distribution::Client> = OnceLock::new();
static OCI_CLIENT_HTTP: OnceLock<oci_distribution::Client> = OnceLock::new();

fn get_oci_client(is_http: bool) -> &'static oci_distribution::Client {
    if is_http {
        OCI_CLIENT_HTTP.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig {
                protocol: oci_distribution::client::ClientProtocol::Http,
                ..Default::default()
            };
            oci_distribution::Client::new(client_config)
        })
    } else {
        OCI_CLIENT_HTTPS.get_or_init(|| {
            let client_config = oci_distribution::client::ClientConfig::default();
            oci_distribution::Client::new(client_config)
        })
    }
}

/// Is `host` a cloud-metadata service hostname or IP literal?
///
/// These hosts MUST NEVER appear as an OCI registry — they exist only
/// to serve short-lived credentials to the workload running on that
/// VM. A worker that issues an OCI pull against one of these
/// addresses is being SSRF'd into leaking the controller pod's
/// IMDS/STS token (or whatever the cloud's metadata service hands out
/// to authenticated callers).
///
/// `host` is the registry component of a parsed `oci_distribution::Reference`,
/// which is the hostname-with-optional-port (e.g. `"169.254.169.254:5000"`).
/// The port is stripped before comparison so `169.254.169.254:5000` still
/// matches the IPv4 literal.
///
/// **Cases covered:**
/// * IMDS v1/v2 (AWS, Azure, OpenStack, DigitalOcean): `169.254.169.254`
/// * GCE: `metadata.google.internal` (DNS), `metadata` (short-form),
///   `169.254.169.254` (same IP as AWS)
/// * AWS EC2 IMDSv2 IPv6: `fd00:ec2::254`
/// * Oracle Cloud: `169.254.169.254` (same)
/// * Alibaba Cloud: `100.100.100.200`
///
/// Comparison is case-insensitive for DNS names; IP literals are
/// compared by parsing both sides as `IpAddr` so spelling tricks
/// (`169.254.169.0254`, `0xa9.0xfe.0xa9.0xfe`, `2852039166`) don't
/// bypass — `Ipv4Addr::from_str` accepts only canonical dotted-quad
/// form, but a future hostile encoding could be added here as the
/// threat landscape evolves.
pub(crate) fn is_metadata_service_host(host: &str) -> bool {
    // Strip port. The OCI registry component is one of:
    //   1. `host` — bare DNS / IPv4
    //   2. `host:port` — DNS / IPv4 with port
    //   3. `[v6addr]:port` — IPv6 literal with port (bracketed)
    //   4. `v6addr` — bare IPv6 literal (e.g. `fd00:ec2::254`)
    //
    // The ambiguity is case 4 vs case 2: `fd00:ec2::254` has a final
    // `:254` that looks like a port to a naive `rsplit_once(':')`.
    // We disambiguate by trying to parse the whole string as an
    // IpAddr first — if it parses, no port stripping needed.
    let host_no_port: &str = if host.parse::<std::net::IpAddr>().is_ok() {
        // Bare IPv4 or bare IPv6 — use as-is.
        host
    } else if let Some(end) = host.strip_prefix('[') {
        // `[v6addr]` or `[v6addr]:port` — strip brackets, drop suffix.
        match end.split_once(']') {
            Some((v6, _after_bracket)) => v6,
            None => host, // malformed — let `parse::<IpAddr>` fail below
        }
    } else if let Some((before, after)) = host.rsplit_once(':') {
        // `host:port`. The port suffix must be ASCII digits; otherwise
        // the colon is part of an unbracketed IPv6 (already handled
        // above by the IpAddr parse) and we shouldn't strip.
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
            before
        } else {
            host
        }
    } else {
        host
    };

    // DNS-name matches (case-insensitive).
    let dns_matches = [
        "metadata.google.internal",
        "metadata",
        "metadata.aws.amazon.com",
    ];
    for name in dns_matches {
        if host_no_port.eq_ignore_ascii_case(name) {
            return true;
        }
    }

    // IP-literal matches.
    if let Ok(ip) = host_no_port.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                // 169.254.169.254 — AWS/Azure/GCP/Oracle/DO IMDS.
                if v4.octets() == [169, 254, 169, 254] {
                    return true;
                }
                // 100.100.100.200 — Alibaba Cloud metadata.
                if v4.octets() == [100, 100, 100, 200] {
                    return true;
                }
            }
            std::net::IpAddr::V6(v6) => {
                // fd00:ec2::254 — AWS IMDSv2 IPv6.
                // Decompresses to `fd00:0ec2:0:0:0:0:0:0254`, so the
                // segment layout is `[0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]`.
                let segs = v6.segments();
                if segs == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod is_metadata_service_host_tests {
    use super::is_metadata_service_host;

    #[test]
    fn aws_imds_v4_blocked() {
        assert!(is_metadata_service_host("169.254.169.254"));
        assert!(is_metadata_service_host("169.254.169.254:80"));
        assert!(is_metadata_service_host("169.254.169.254:5000"));
    }

    #[test]
    fn alibaba_metadata_blocked() {
        assert!(is_metadata_service_host("100.100.100.200"));
        assert!(is_metadata_service_host("100.100.100.200:80"));
    }

    #[test]
    fn aws_imds_v6_blocked() {
        // fd00:ec2::254 (unbracketed)
        assert!(is_metadata_service_host("fd00:ec2::254"));
        // bracketed with port
        assert!(is_metadata_service_host("[fd00:ec2::254]:443"));
    }

    #[test]
    fn gce_metadata_dns_blocked() {
        assert!(is_metadata_service_host("metadata.google.internal"));
        assert!(is_metadata_service_host("METADATA.GOOGLE.INTERNAL"));
        assert!(is_metadata_service_host("metadata"));
        assert!(is_metadata_service_host("Metadata"));
        assert!(is_metadata_service_host("metadata.google.internal:80"));
    }

    #[test]
    fn legitimate_registries_allowed() {
        // Local-cluster setups must not be blocked.
        assert!(!is_metadata_service_host("ghcr.io"));
        assert!(!is_metadata_service_host("registry:5000"));
        assert!(!is_metadata_service_host("localhost:5000"));
        assert!(!is_metadata_service_host("127.0.0.1:5000"));
        assert!(!is_metadata_service_host("registry.svc.cluster.local"));
        // Public registries.
        assert!(!is_metadata_service_host("docker.io"));
        assert!(!is_metadata_service_host("quay.io"));
        assert!(!is_metadata_service_host("us-docker.pkg.dev"));
    }

    #[test]
    fn near_misses_allowed() {
        // Unicode lookalikes — host_no_port comparison is byte-exact for IPs.
        // The host parser would have rejected non-ASCII anyway, but defense in depth.
        assert!(!is_metadata_service_host("169.254.169.253"));
        assert!(!is_metadata_service_host("169.254.169.255"));
        // Different but related private ranges.
        assert!(!is_metadata_service_host("169.254.0.1"));
        // Not a registry name pattern.
        assert!(!is_metadata_service_host("registry-metadata.example.com"));
    }
}

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
/// Removes: file paths, line numbers, internal IP addresses.
/// Truncates to 2000 characters (Unicode-safe).
fn sanitize_error_message(error: &str) -> String {
    let mut sanitized = error.to_string();

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

// ============================================================================
// RELIABILITY: Result Publishing with Retry
// ============================================================================

/// Publish a serialized payload to a NATS topic with exponential backoff retry.
async fn publish_bytes_with_retry(
    nc: &async_nats::Client,
    topic: String,
    payload: bytes::Bytes,
    max_attempts: u32,
) -> Result<(), String> {
    let mut backoff_ms = 100u64;
    for attempt in 0..max_attempts {
        match nc.publish(topic.clone(), payload.clone()).await {
            Ok(_) => {
                if attempt > 0 {
                    ::tracing::info!(topic, attempt, "Published after retries");
                }
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts - 1 {
                    ::tracing::warn!(
                        topic,
                        attempt = attempt + 1,
                        max_attempts,
                        error = %e,
                        "Failed to publish, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(5_000);
                } else {
                    return Err(format!(
                        "Failed to publish to {} after {} attempts: {}",
                        topic, max_attempts, e
                    ));
                }
            }
        }
    }
    Err("Unexpected retry loop exit".to_string())
}

/// Publish result to NATS with exponential backoff retry.
///
/// Single-publish architecture (post-r301): the result is published to
/// EXACTLY ONE subject per call:
///
///  * `Some(reply)` (NATS request-reply): publish to the inbox the
///    requester is awaiting on. The requester (engine dispatcher,
///    webhook dispatcher, gmail/gcal handlers, etc.) verifies the
///    result inline and writes durable state through its own path.
///  * `None` (true fire-and-forget): publish to the global
///    `talos.results.{job_id}` topic so the controller's
///    `talos.results.*` audit subscriber can update `module_executions`
///    durably. There is no inline requester to consume the reply.
///
/// Pre-r301 the worker dual-published to BOTH the reply inbox AND
/// `talos.results.{job_id}` "for logging/audit". The controller had
/// two verifiers consuming these (the dispatcher + the audit
/// subscriber) and both ran `JobResult::verify()`, sharing the
/// process-local `JOB_NONCE_CACHE`. Once `WORKER_SHARED_KEY` started
/// loading reliably (post-r294 vault bootstrap fix), the second
/// verifier always hit "result_nonce already seen" and EVERY workflow
/// execution failed (r300 was the protocol-level mitigation;
/// single-publish is the source-level architectural fix).
///
/// Today, every NATS-dispatched path uses request-reply (engine,
/// webhooks, gmail, gcal); `run_sandbox` and `test_module` run WASM
/// in-process and don't hit NATS at all. Audit subscriber-only paths
/// don't currently exist, but the fire-and-forget code path is kept
/// for future use (e.g. async work-queue dispatches that don't await
/// the result inline).
/// H-1: Reconcile the wire-format NATS `msg.reply` (untrusted —
/// flows over an unsigned header an attacker can modify) with the
/// HMAC-bound `JobRequest::reply_topic` (signed, trustworthy when
/// present). Returns the subject the worker SHOULD publish the
/// signed JobResult to, or `None` if no reply path is available.
///
/// Decision matrix:
/// - (Some(signed), Some(wire)) where signed == wire → trust both;
///   return Some(signed). Hot path.
/// - (Some(signed), Some(wire)) where signed != wire → log a
///   SECURITY-level warning AND publish to the SIGNED value. The
///   wire value is attacker-controllable; the signed value is the
///   one the controller committed to.
/// - (Some(signed), None) → publish to the signed value. Indicates
///   the wire header was stripped in transit (rare; treat the
///   signed value as authoritative).
/// - (None, Some(wire)) → publish to the wire value. Backward-compat
///   path for controllers / transports that don't pre-allocate
///   inboxes. The legacy "trust msg.reply" exposure remains but
///   only when reply_topic isn't bound.
/// - (None, None) → no reply path; the worker logs the result
///   elsewhere (e.g. fire-and-forget topic).
///
/// Pure function so the policy is unit-testable without a NATS
/// broker. The `job_id` parameter is for log correlation only.
pub(crate) fn pick_trusted_reply_topic(
    job_id: uuid::Uuid,
    signed: Option<&str>,
    wire: Option<&str>,
) -> Option<String> {
    match (signed, wire) {
        (Some(s), Some(w)) if s == w => Some(s.to_string()),
        (Some(s), Some(w)) => {
            ::tracing::error!(
                job_id = %job_id,
                signed_reply = %s,
                wire_reply = %w,
                "SECURITY: H-1 reply_topic mismatch — wire msg.reply does not match \
                 HMAC-bound JobRequest.reply_topic. Publishing to the SIGNED value; \
                 wire value is likely attacker-tampered."
            );
            Some(s.to_string())
        }
        (Some(s), None) => {
            ::tracing::warn!(
                job_id = %job_id,
                signed_reply = %s,
                "H-1: msg.reply stripped in transit; publishing to HMAC-bound reply_topic"
            );
            Some(s.to_string())
        }
        (None, Some(w)) => Some(w.to_string()),
        (None, None) => {
            // L-12 (2026-05-22): the result will be published to the
            // global `talos.results.{job_id}` topic by the caller
            // (publish_result_with_retry). That path is intended for the
            // controller's audit subscriber — but if neither the
            // signed `reply_topic` NOR the wire `msg.reply` is set AND
            // the operator hasn't configured an audit subscriber, the
            // result effectively disappears (broker delivers to zero
            // subscribers, no error returned). Emit a structured event
            // here so the condition is visible in dashboards and a
            // misconfigured dispatch path doesn't degrade silently.
            //
            // `target: "talos_worker_metrics"` lets operators alert via
            // a single filter; `event_kind` is the stable identifier.
            ::tracing::warn!(
                target: "talos_worker_metrics",
                job_id = %job_id,
                event_kind = "job_result_no_reply",
                "neither signed reply_topic nor wire msg.reply set — result \
                 will publish to the global audit topic only. If no audit \
                 subscriber is configured this result is lost."
            );
            None
        }
    }
}

/// L-11 (2026-05-22): The worker's self-reported identity, bound into
/// every signed [`talos_workflow_job_protocol::JobResult`] /
/// [`talos_workflow_job_protocol::PipelineJobResult`] via
/// `sign_with_worker_id`.
///
/// Thin wrapper around [`worker::worker_identity`] — the canonical
/// resolver lives in the library so both the binary AND library code
/// (e.g. `host_impl::build_signed_agent_envelope`) share the same
/// `OnceLock`-cached value. Pre-extraction this function lived in the
/// binary only; a library callsite would have built a SECOND cache
/// with a possibly-different fallback id, breaking forensic
/// attribution at signed-envelope subscribers.
pub(crate) fn worker_identity() -> &'static str {
    crate::worker_identity::worker_identity()
}

#[cfg(test)]
mod worker_identity_tests {
    use super::worker_identity;

    #[test]
    fn returns_validatable_id() {
        let id = worker_identity();
        // Whatever the resolution branch, the output must satisfy the
        // protocol's validator — that's what the worker is going to
        // pass to `sign_with_worker_id` in production.
        talos_workflow_job_protocol::validate_worker_id(id)
            .expect("resolved worker_id must satisfy validate_worker_id");
    }

    #[test]
    fn cached_across_calls() {
        // OnceLock semantics: stable address means stable string.
        let a: &'static str = worker_identity();
        let b: &'static str = worker_identity();
        assert_eq!(a.as_ptr(), b.as_ptr(), "worker_identity must be cached");
    }
}

/// M-7: Hard ceiling on the serialized JobResult bytes the worker
/// will attempt to publish to NATS. Without a pre-publish cap, an
/// oversized `output_payload` (legitimately large or hostile) silently
/// fails at the broker layer (default NATS `max_payload` is 1 MiB)
/// and the controller times out waiting for a reply that will never
/// arrive. The worker has already done the work; the failure is in
/// the last-mile transport with no signal to either side.
///
/// 4 MiB matches the typical `max_payload` we configure on the NATS
/// JetStream servers in production (it can be bumped via NATS config).
/// `WORKER_MAX_JOB_RESULT_BYTES=0` falls back to the default; an
/// explicit positive value overrides.
const DEFAULT_MAX_JOB_RESULT_BYTES: usize = 4 * 1024 * 1024;

fn max_job_result_bytes() -> usize {
    std::env::var("WORKER_MAX_JOB_RESULT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_JOB_RESULT_BYTES)
}

/// M-7: Replace an oversized `JobResult` with a small "output too
/// large" error result that still signs and publishes successfully.
/// Pure data transform so the policy is unit-testable.
///
/// Preserves `job_id`, `status` (downgraded to `Failed`), and
/// `execution_time_ms` so callers can still correlate; drops the
/// oversized `output_payload` and `logs` (replaces with a single
/// diagnostic line). The new result MUST be re-signed by the caller
/// before publishing — the signature carries `output_hash` so it
/// would be invalid otherwise.
fn truncate_oversized_job_result(
    result: &JobResult,
    serialized_len: usize,
    cap: usize,
) -> JobResult {
    JobResult {
        job_id: result.job_id,
        status: JobStatus::Failed,
        output_payload: serde_json::json!({
            "error": "job_result_too_large",
            "diag": {
                "serialized_bytes": serialized_len,
                "cap_bytes": cap,
                "note": "Worker dropped the original output_payload to keep \
                         under WORKER_MAX_JOB_RESULT_BYTES. Reduce module \
                         output size or raise the cap if this is legitimate."
            }
        }),
        logs: vec![format!(
            "[host] dropped {serialized_len}-byte result (cap {cap})"
        )],
        execution_time_ms: result.execution_time_ms,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
    }
}

async fn publish_result_with_retry(
    nc: &async_nats::Client,
    result: &JobResult,
    max_attempts: u32,
    reply_topic: Option<String>,
    shared_key: &talos_workflow_engine_core::WorkerKeyRing,
) -> Result<(), String> {
    // Serialize once so we can size-check before deciding how to
    // publish. serde_json::to_vec on a JobResult is cheap (single
    // pass) and we'd serialize anyway downstream.
    let serialized = match serde_json::to_vec(&result) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("Failed to serialize result: {}", e));
        }
    };

    let cap = max_job_result_bytes();
    let payload = if serialized.len() > cap {
        // M-7: degrade to a "result too large" error message so the
        // controller gets a signed Failed status instead of a silent
        // broker rejection + timeout. Sign the replacement; bail with
        // a Err only if signing itself fails (which would indicate the
        // shared key is mis-configured and is already loud upstream).
        ::tracing::error!(
            job_id = %result.job_id,
            serialized_bytes = serialized.len(),
            cap_bytes = cap,
            "JobResult exceeds NATS publish cap — substituting a small Failed result so the controller doesn't time out"
        );
        let mut replacement = truncate_oversized_job_result(result, serialized.len(), cap);
        // L-11: bind the worker's identity into the signature so the
        // controller's audit log records which pod emitted the
        // truncated-replacement result. See `worker_identity` for the
        // resolution chain.
        if let Err(e) =
            replacement.sign_with_worker_id(shared_key.signing_key().as_bytes(), worker_identity())
        {
            return Err(format!("Failed to sign oversized-result replacement: {e}"));
        }
        match serde_json::to_vec(&replacement) {
            Ok(v) => bytes::Bytes::from(v),
            Err(e) => return Err(format!("Failed to serialize replacement: {e}")),
        }
    } else {
        bytes::Bytes::from(serialized)
    };

    if let Some(reply) = reply_topic {
        publish_bytes_with_retry(nc, reply, payload, max_attempts).await
    } else {
        let result_topic = format!("talos.results.{}", result.job_id);
        publish_bytes_with_retry(nc, result_topic, payload, max_attempts).await
    }
}

/// Per-job span adapter backed by the current `#[::tracing::instrument]` span.
///
/// Presents the same surface the job/pipeline handlers already use
/// (`set_attribute` / `set_attribute_int` / `add_event` / `end_error` /
/// `end_success`) but routes everything through the `tracing` span via
/// [`tracing_opentelemetry::OpenTelemetrySpanExt`], so attributes/events/status
/// flow through the otel bridge layer (and host-function child spans nest under
/// it). This replaces the manual-otel `ExecutionSpan` for the per-job span now
/// that the worker exports `tracing` spans to OTLP; `ExecutionSpan` remains for
/// the standalone `wasm-execution` span in `runtime.rs`.
struct JobSpan {
    span: ::tracing::Span,
}

impl JobSpan {
    /// Wrap the current instrument span and link it to the propagated controller
    /// trace context, so the worker job span nests under the controller
    /// `workflow` span rather than starting a fresh root trace.
    fn current_with_parent(cx: &opentelemetry::Context) -> Self {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let span = ::tracing::Span::current();
        // `set_parent` only errors if the context carries no span; ignore — a
        // missing parent simply yields a root job span (e.g. module-bound jobs).
        let _ = span.set_parent(cx.clone());
        Self { span }
    }

    fn set_attribute(&mut self, key: &str, value: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_attribute(key.to_string(), value.to_string());
    }

    fn set_attribute_int(&mut self, key: &str, value: i64) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_attribute(key.to_string(), value);
    }

    fn add_event(&mut self, name: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.add_event(name.to_string(), Vec::new());
    }

    fn end_error(self, message: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span
            .set_status(opentelemetry::trace::Status::error(message.to_string()));
    }

    fn end_success(self) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_status(opentelemetry::trace::Status::Ok);
    }
}

/// Execute the Wasm module for a given job with observability.
///
/// * Verifies the HMAC signature before executing.
/// * Decrypts secrets from `req.encrypted_secrets` using the shared key.
/// * Passes decrypted secrets to the runtime so WASM modules can access them
///   via the `secrets::get-secret` host function.
#[::tracing::instrument(name = "job-execution", skip_all)]
async fn execute_job(
    cx: &opentelemetry::Context,
    req: JobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerKeyRing,
) -> JobResult {
    let start = std::time::Instant::now();

    // The `#[instrument]` span above is THE job span; wrap it and link it to the
    // propagated controller trace context. All `_span.*` calls below set
    // attributes / events / status on it, exported via the otel bridge layer.
    let mut _span = JobSpan::current_with_parent(cx);
    _span.set_attribute("job_id", &req.job_id.to_string());
    _span.set_attribute("module_uri", &req.module_uri);

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    // Ring-aware: accepts the current key OR a staged WORKER_SHARED_KEY_PREVIOUS
    // so a rolling rotation doesn't reject controller-signed jobs.
    if let Err(e) = req.verify_with_ring(&shared_key, 300) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");

        // MCP-1212 (2026-05-18): diagnostic enrichment for signature
        // verification failures. Pre-fix the worker emitted an opaque
        // "signature verification failed" string with no way for the
        // operator to identify which signed field diverged between
        // controller and worker. Recompute the same per-field hashes
        // that `signing_payload()` consumes and surface them in
        // output_payload so `get_execution_status` shows the worker's
        // view side-by-side with the underlying error. The controller
        // side logs the same fields at WARN level
        // (target: "signature_diag") so operators can grep their
        // controller logs and find the controller's view for direct
        // comparison. `diag_hashes()` is the canonical helper, colocated
        // with `signing_payload()` in job-protocol so the field formulas
        // stay in sync across controller + worker.
        let (worker_input_hash, worker_secrets_hash, worker_input_byte_len) = req.diag_hashes();
        let signature_byte_len = req.signature.len();

        return JobResult {
            job_id: req.job_id,
            status: JobStatus::Failed,
            output_payload: json!({
                "error": "signature verification failed",
                "diag": {
                    "verify_error": e,
                    "worker_input_hash": worker_input_hash,
                    "worker_secrets_hash": worker_secrets_hash,
                    "worker_input_byte_len": worker_input_byte_len,
                    "signature_byte_len": signature_byte_len,
                    "job_nonce": req.job_nonce,
                    "module_uri": req.module_uri,
                    "actor_id": req.actor_id.map(|u| u.to_string()),
                    "user_id": req.user_id.to_string(),
                    "allowed_hosts": req.allowed_hosts,
                    "allowed_methods": req.allowed_methods,
                    "allowed_secrets": req.allowed_secrets,
                    "allowed_sql_operations": req.allowed_sql_operations,
                    "allow_tier2_exposure": req.allow_tier2_exposure,
                    "integration_name": req.integration_name,
                    "expected_wasm_hash": req.expected_wasm_hash,
                    "timeout_ms": req.timeout_ms,
                    "note": "Compare these worker-computed values against the controller's `signature_diag` WARN log entry for the same job_id to identify which signed field diverged."
                }
            }),
            logs: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // DEADLINE CHECK: Reject jobs whose deadline has already passed.
    if req.deadline_unix_secs > 0 {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs > req.deadline_unix_secs {
            _span.set_attribute("error", "deadline_expired");
            _span.end_error("Job deadline expired before execution started");
            return JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": "job deadline expired"}),
                logs: vec![],
                execution_time_ms: start.elapsed().as_millis() as u64,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            };
        }
    }

    // SECURITY: Decrypt secrets from the encrypted payload.
    // L-1 (2026-05-22): AAD = workflow_execution_id. Controller-side
    // encryption binds this same identifier into the AES-GCM tag, so
    // a ciphertext transposed between executions (under the same
    // shared key) fails the tag check here. The execution_id is
    // already HMAC-bound in the JobRequest signing payload, so it
    // can't be tampered with on the wire.
    let secrets: HashMap<String, String> = if req.encrypted_secrets.is_empty() {
        HashMap::new()
    } else {
        match req
            .encrypted_secrets
            .decrypt_with_ring(&shared_key, req.workflow_execution_id.as_bytes())
        {
            Ok(s) => s,
            Err(e) => {
                ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt job secrets");
                _span.end_error("Secret decryption failed");

                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: json!({"error": "failed to decrypt job secrets"}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
        }
    };

    // Load the Wasm module bytes.
    //
    // SECURITY: track whether the bytes we end up executing were
    // cryptographically attested during THIS worker run:
    // * inline `wasm_bytes` from a JobRequest — HMAC over the job covers
    //   sha256(bytes), so attested by the signing key.
    // * Fresh OCI pull that completed Sigstore + layer-digest checks.
    // The opposite (NOT attested in this run): a Redis cache hit used as
    // OCI fallback, a `redis:wasm:` direct fetch, or a filesystem load.
    // For unattested bytes, `expected_wasm_hash` from the controller is
    // the only thing standing between us and a Redis-write attacker
    // substituting malicious WASM. The verification block downstream
    // refuses to execute unattested bytes when no hash is supplied.
    let mut bytes_attested_in_this_run = false;
    _span.add_event("loading_module");
    let wasm_bytes = if let Some(bytes) = &req.wasm_bytes {
        // PERFORMANCE: Use bytes provided in job request (avoids file I/O)
        // HMAC over the JobRequest covers sha256(bytes) — attested.
        _span.set_attribute_int("module_size_bytes", bytes.len() as i64);
        _span.set_attribute("module_source", "job_request");
        bytes_attested_in_this_run = true;
        bytes.clone()
    } else if req.module_uri.starts_with("oci://") {
        // Fetch from OCI Registry (e.g. GitHub Container Registry, AWS ECR, JFrog)
        _span.add_event("fetching_from_oci_registry");
        _span.set_attribute("oci_url", &req.module_uri);

        // Strip the "oci://" prefix
        let mut image_ref = req
            .module_uri
            .strip_prefix("oci://")
            .unwrap_or(&req.module_uri)
            .to_string();

        if image_ref.starts_with("localhost:5001") {
            image_ref = image_ref.replace("localhost:5001", "registry:5000");
        }

        // H1 (2026-05-22): cache lookup is digest-keyed, not URI-keyed.
        // Pre-fix the cache used `oci_cache:{module_uri}` which, for
        // mutable tags like `…:latest`, served whatever bytes the
        // previous pull stored — even if the registry had since
        // repointed the tag to different bytes. With the digest in the
        // key, a tag repoint produces a fresh cache entry under the
        // new digest; the old entry expires naturally on its TTL.
        //
        // The lookup itself is deferred until AFTER we've fetched the
        // manifest below — only then do we know the canonical layer
        // digest for THIS tag at THIS moment. Manifest fetch is small
        // (a few KB of JSON, no decompression); for high-throughput
        // workloads this adds one round-trip per execution but
        // eliminates the cache-poisoning window.
        let mut found_bytes: Option<Vec<u8>> = None;

        use oci_distribution::secrets::RegistryAuth;
        use oci_distribution::Reference;

        if let Ok(reference) = image_ref.parse::<Reference>() {
            // SECURITY: registry-host SSRF gate.
            //
            // The module_uri is HMAC-bound in the JobRequest, so an
            // on-wire attacker can't redirect us to a different
            // registry. But a compromised controller — or a stored
            // module record pointing at the wrong host — could try to
            // point the worker at a metadata-service endpoint and
            // exfiltrate cloud creds. We refuse to make ANY OCI
            // request against a known metadata-service hostname / IP
            // regardless of other gates.
            //
            // NOT a blanket RFC-1918 block: legitimate setups use
            // localhost:5000 / registry:5000 / kube DNS like
            // registry.svc.cluster.local. We only refuse hosts that
            // are NEVER legitimate registries. Sigstore verification
            // would catch unsigned bytes from any host anyway, but
            // the metadata-service exposure is the worst-case (token
            // leak via HTTP body / headers / error message); fail
            // closed BEFORE making the network round-trip.
            if is_metadata_service_host(reference.registry()) {
                let err = "registry_host_denied: cloud metadata service host \
                     is never a legitimate OCI registry"
                    .to_string();
                ::tracing::error!(
                    module_uri = %req.module_uri,
                    registry = %reference.registry(),
                    "OCI fetch attempted against cloud metadata host — refusing"
                );
                _span.end_error(&err);
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": err}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }

            // In a development environment with a local registry, we need to allow HTTP.
            // SECURITY: Ensure HTTP downgrade is never allowed in production.
            // MCP-668 (2026-05-13): route through `talos_config::is_production()`
            // so an empty `RUST_ENV=""` from a helm placeholder doesn't
            // bypass the production gate. Raw `unwrap_or_default()` would
            // compare `"" == "production"` → false → fail OPEN.
            let is_prod = talos_config::is_production();
            let is_local_registry = image_ref.starts_with("registry:5000")
                || image_ref.starts_with("localhost:")
                || image_ref.starts_with("127.0.0.1:");

            let is_http = if is_local_registry && !is_prod {
                true
            } else if is_local_registry && is_prod {
                let err_msg =
                    "SECURITY: Denied HTTP downgrade for OCI fetch in production environment"
                        .to_string();
                ::tracing::error!("{}", err_msg);
                _span.end_error(&err_msg);
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": err_msg}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            } else {
                false
            };

            // MCP-913: direct &Client — see OCI_CLIENT_HTTPS/HTTP comment for
            // why the prior `client_mutex.lock().await` was a concurrency
            // bottleneck. `Client::pull` is `&self` and thread-safe.
            let client = get_oci_client(is_http);

            // In a production enterprise setting, these would be loaded from HashiCorp Vault or mounted Secrets.
            // MCP-762 (2026-05-13): match the sibling helper
            // `talos-registry::sync::registry_auth_from_env` (sync.rs:547)
            // by filtering empty strings before constructing
            // RegistryAuth::Basic. Pre-fix, `OCI_REGISTRY_USERNAME=""`
            // (helm placeholder pattern) yielded `Ok("")` from
            // std::env::var, took the `if let (Ok, Ok)` branch, and
            // produced `RegistryAuth::Basic("", "")` — sent as
            // `Authorization: Basic Og==` (base64 of `:`). The registry
            // rejects with 401 instead of falling back to the
            // documented anonymous-for-public-artifacts path. Same
            // empty-env-var class as MCP-590/591/653/710/752/753; the
            // controller-side `registry_auth_from_env` had the right
            // shape but the worker-side resolver was the drift.
            let user_opt = std::env::var("OCI_REGISTRY_USERNAME")
                .ok()
                .filter(|v| !v.is_empty());
            let pass_opt = std::env::var("OCI_REGISTRY_PASSWORD")
                .ok()
                .filter(|v| !v.is_empty());
            let auth = match (user_opt, pass_opt) {
                (Some(user), Some(password)) => RegistryAuth::Basic(user, password),
                _ => RegistryAuth::Anonymous,
            };

            let accepted_media_types = vec!["application/vnd.wasm.content.layer.v1+wasm"];

            // Sigstore signature verification — runs BEFORE the OCI pull
            // body is processed, so an unsigned or tampered artifact never
            // gets executed OR cached. Policy is process-wide (resolved
            // once from env at startup); enforcement happens per-pull so
            // operators can flip from Audit → Required without restarting.
            //
            // SECURITY: this is the runtime trust boundary. Disabled mode
            // is for dev only — production deploys MUST set
            // TALOS_SIGSTORE_REQUIRED=true.
            //
            // `sigstore_pass_in_this_run` tracks the verdict so we can
            // skip the Redis cache write on Audit-mode failure: a future
            // pull would otherwise serve attacker-controlled bytes from
            // cache without re-verifying signature. Required mode is
            // already fail-closed (returns Failed below), so this flag
            // is only consulted for the Audit-failure path.
            //
            // Starts `true` because Disabled mode + missing-identity-in-
            // Audit-mode both fall through without a verification
            // attempt; treating those as "attested" preserves
            // operator-chosen intent (Disabled = trust the registry;
            // Audit-with-missing-identity = misconfiguration warning,
            // not a verification failure).
            let mut sigstore_pass_in_this_run = true;
            let sigstore_policy = SigstorePolicy::from_env();
            if sigstore_policy != SigstorePolicy::Disabled {
                let identity_regexp =
                    std::env::var("TALOS_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
                // MCP-752 (2026-05-13): filter empty so a helm-rendered
                // `TALOS_SIGSTORE_OIDC_ISSUER=""` doesn't bypass the default.
                // Pre-fix, `unwrap_or_else(|_| default)` only fired on the
                // env-unset path — `Ok("")` from a placeholder helm value
                // passed `""` verbatim into `cosign verify
                // --certificate-oidc-issuer ""`, weakening the documented
                // defense-in-depth that pins certificates to GitHub Actions
                // OIDC tokens specifically (per CLAUDE.md "Sigstore identity
                // regexp pins to the workflow URL ... The OIDC issuer pin
                // restricts to GitHub Actions tokens specifically. Without
                // ... either omission lets a valid Sigstore signature from
                // any other workflow on any other repo pass verification.").
                // Same empty-env class as MCP-590/591/653/710. The sibling
                // `identity_regexp` is already fail-closed in `Required`
                // mode at the check below — this fix completes the symmetry
                // by ensuring the `oidc_issuer` argument can never be empty
                // when `cosign` is invoked.
                let oidc_issuer = std::env::var("TALOS_SIGSTORE_OIDC_ISSUER")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "https://token.actions.githubusercontent.com".to_string());
                if identity_regexp.is_empty() {
                    let err = "TALOS_SIGSTORE_IDENTITY_REGEXP must be set when \
                               TALOS_SIGSTORE_REQUIRED is enabled"
                        .to_string();
                    ::tracing::error!("{}", err);
                    if sigstore_policy == SigstorePolicy::Required {
                        _span.end_error(&err);
                        return JobResult {
                            job_id: req.job_id,
                            status: JobStatus::Failed,
                            output_payload: serde_json::json!({"error": err}),
                            logs: vec![],
                            execution_time_ms: start.elapsed().as_millis() as u64,
                            signature: vec![],
                            result_nonce: String::new(),
                            worker_id: String::new(),
                        };
                    }
                } else {
                    match verify_oci_signature(&image_ref, &identity_regexp, &oidc_issuer).await {
                        Ok(()) => {
                            _span.add_event("sigstore_verify_ok");
                        }
                        Err(reason) => match sigstore_policy {
                            SigstorePolicy::Required => {
                                let err = format!("sigstore_required: {reason}");
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    "Sigstore verification failed and policy is required — refusing to execute"
                                );
                                _span.end_error(&err);
                                return JobResult {
                                    job_id: req.job_id,
                                    status: JobStatus::Failed,
                                    output_payload: serde_json::json!({"error": err}),
                                    logs: vec![],
                                    execution_time_ms: start.elapsed().as_millis() as u64,
                                    signature: vec![],
                                    result_nonce: String::new(),
                                    worker_id: String::new(),
                                };
                            }
                            SigstorePolicy::Audit => {
                                ::tracing::warn!(
                                    module_uri = %req.module_uri,
                                    reason = %reason,
                                    "Sigstore verification failed but policy is audit — \
                                     continuing execution but NOT caching bytes"
                                );
                                _span.add_event("sigstore_verify_failed_audit");
                                // Mark this pull unattested so the
                                // Redis-cache write below is skipped.
                                // Without this, an Audit-mode failure
                                // poisons the cache: the same module_uri
                                // would short-circuit signature
                                // verification on the next request
                                // (cache hits bypass the full OCI path).
                                // Operators flipping from Audit →
                                // Required mid-flight would not
                                // re-verify cached entries.
                                sigstore_pass_in_this_run = false;
                            }
                            SigstorePolicy::Disabled => unreachable!(),
                        },
                    }
                }
            }

            // H-3: pre-pull manifest size gate. Fetch the manifest by
            // itself first (small payload, no decompression) and refuse
            // to pull the full image if any layer's declared size
            // exceeds the cap. Without this, a hostile registry could
            // serve a gzipped 100 MB layer that decompresses to 10 GB
            // and OOMs the worker before any of our integrity checks
            // (Sigstore, layer-digest, hash) run.
            //
            // H1 (2026-05-22): the manifest fetch also tells us the
            // canonical LAYER digest for this tag at this moment. We
            // use that digest to key the Redis cache so a tag-repoint
            // produces a fresh cache entry under the new digest. The
            // manifest fetch is small (a few KB of JSON, no
            // decompression); for high-throughput workloads this adds
            // one round-trip per execution but eliminates the
            // cache-poisoning window that existed when the cache was
            // URI-keyed.
            let layer_cap = max_oci_layer_bytes();
            let mut expected_layer_digest: Option<String> = None;
            match client.pull_manifest(&reference, &auth).await {
                Ok((manifest, _manifest_digest)) => {
                    // `pull_manifest` returns either an Image manifest
                    // (single-arch artifact, has `.layers`) or an
                    // ImageIndex (multi-arch fan-out, has `.manifests`).
                    // Wasm artifacts are single-arch in practice;
                    // ImageIndex would mean the registry returned a
                    // multi-arch image list which we don't currently
                    // support. Match both shapes — ImageIndex falls
                    // through to `pull()` which handles it (or errors).
                    let (declared_sizes, layer_digest) = match &manifest {
                        oci_distribution::manifest::OciManifest::Image(img) => {
                            let sizes: Vec<i64> = img.layers.iter().map(|d| d.size).collect();
                            let digest = img.layers.first().map(|d| d.digest.clone());
                            (sizes, digest)
                        }
                        oci_distribution::manifest::OciManifest::ImageIndex(_) => {
                            (Vec::new(), None)
                        }
                    };
                    expected_layer_digest = layer_digest;
                    if let ManifestSizeVerdict::Oversized { declared, cap } =
                        check_manifest_layer_sizes(&declared_sizes, layer_cap)
                    {
                        let err = format!(
                            "oci_layer_too_large: manifest declares layer of {declared} bytes, \
                             cap is {cap} (set WORKER_MAX_OCI_LAYER_BYTES to override)"
                        );
                        ::tracing::error!(
                            module_uri = %req.module_uri,
                            declared_size = declared,
                            cap_bytes = cap,
                            "OCI manifest declares oversized layer — refusing to pull"
                        );
                        _span.end_error(&err);
                        return JobResult {
                            job_id: req.job_id,
                            status: JobStatus::Failed,
                            output_payload: serde_json::json!({"error": err}),
                            logs: vec![],
                            execution_time_ms: start.elapsed().as_millis() as u64,
                            signature: vec![],
                            result_nonce: String::new(),
                            worker_id: String::new(),
                        };
                    }
                }
                Err(e) => {
                    // Don't fail closed here — fall through to `pull()`
                    // and let it report the real error (could be auth,
                    // not-found, etc.). The defense-in-depth `data.len()`
                    // check below still guards against the actual OOM.
                    // Note: without a manifest fetch we have no
                    // canonical layer digest, so the cache lookup
                    // below is a no-op and the M2 hardening
                    // (`refuse_unverified_oci_manifests`) will refuse
                    // the pull bytes too unless explicitly opted in.
                    ::tracing::debug!(
                        module_uri = %req.module_uri,
                        error = %e,
                        "pull_manifest pre-check failed — proceeding to pull() which will report the real error"
                    );
                }
            }

            // H1: digest-keyed cache lookup. Only runs when we
            // successfully resolved a layer digest from the manifest
            // above — otherwise there's nothing safe to key off.
            //
            // Cache hit re-verifies the cached bytes against the
            // expected digest before serving (defense in depth against
            // a Redis-write attacker). The cache is ONLY written below
            // after both sigstore + digest checks pass in this run, so
            // a hit implies prior attestation; we mark
            // `bytes_attested_in_this_run` accordingly so the
            // downstream `expected_wasm_hash` fallback doesn't kick in
            // and re-fail for cached-but-no-hash-provided jobs.
            let redis_key = expected_layer_digest
                .as_ref()
                .map(|d| format!("oci_cache:{}", d));
            if let (Some(digest), Some(key)) = (&expected_layer_digest, &redis_key) {
                if let Some(redis_client) = runtime.redis_client() {
                    if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                        if let Ok(Some(b)) = redis::cmd("GET")
                            .arg(key)
                            .query_async::<Option<Vec<u8>>>(&mut conn)
                            .await
                        {
                            if (b.len() as u64) > layer_cap {
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    cached_size = b.len(),
                                    cap_bytes = layer_cap,
                                    "Redis OCI cache hit exceeds layer cap — discarding cache entry, will refetch from registry"
                                );
                                let _: Result<(), _> = redis::cmd("DEL")
                                    .arg(key)
                                    .query_async::<()>(&mut conn)
                                    .await;
                            } else {
                                // Re-verify cached bytes against the
                                // declared digest. A Redis-write
                                // attacker who replaced the value but
                                // not the key would fail here.
                                match verify_oci_layer(&b, Some(digest.as_str())) {
                                    LayerVerdict::Verified { .. } => {
                                        _span.add_event("oci_cache_hit");
                                        _span.set_attribute("module_source", "redis_oci_cache");
                                        bytes_attested_in_this_run = true;
                                        found_bytes = Some(b);
                                    }
                                    LayerVerdict::DigestMismatch { expected, computed } => {
                                        ::tracing::error!(
                                            module_uri = %req.module_uri,
                                            expected = %expected,
                                            computed = %computed,
                                            "Redis OCI cache hit failed digest re-verification — evicting and refetching"
                                        );
                                        let _: Result<(), _> = redis::cmd("DEL")
                                            .arg(key)
                                            .query_async::<()>(&mut conn)
                                            .await;
                                    }
                                    LayerVerdict::AcceptedUnverified => {
                                        // Unreachable: we passed
                                        // Some(digest) above so the
                                        // None arm doesn't fire. Belt-
                                        // and-braces: evict to force a
                                        // fresh pull rather than serving
                                        // unverified bytes.
                                        let _: Result<(), _> = redis::cmd("DEL")
                                            .arg(key)
                                            .query_async::<()>(&mut conn)
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Only do the full layer pull on cache miss. The pull is
            // the expensive part (network + decompression); on cache
            // hit we already have validated bytes and skip it.
            if found_bytes.is_none() {
                match client.pull(&reference, &auth, accepted_media_types).await {
                    Ok(image) => {
                        // The WASM binary is typically the first layer in a Wasm OCI artifact.
                        // Cross-check the layer's actual sha256 against the manifest's
                        // declared digest before trusting the bytes — bytes that don't
                        // match the manifest indicate registry corruption, MITM during
                        // pull (HTTP only — gated to localhost-dev above), or a bug in
                        // the publish pipeline. Verification logic lives in the pure
                        // helper `verify_oci_layer` so the security-critical decision
                        // is unit-testable.
                        if let Some(layer) = image.layers.into_iter().next() {
                            // H-3 defense in depth: even if the manifest
                            // claimed a small layer (pre-pull check passed)
                            // OR the registry skipped the manifest's size
                            // field, refuse if the actual decompressed
                            // bytes exceed the cap. Reject WITHOUT caching
                            // so a poisoned layer doesn't persist in Redis
                            // to OOM the next worker.
                            if (layer.data.len() as u64) > layer_cap {
                                let err = format!(
                                    "oci_layer_too_large_post_pull: actual layer is {} bytes, \
                                 cap is {} (manifest may have lied about declared size)",
                                    layer.data.len(),
                                    layer_cap
                                );
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    actual_size = layer.data.len(),
                                    cap_bytes = layer_cap,
                                    "OCI layer exceeds cap post-pull — refusing to execute or cache"
                                );
                                _span.end_error(&err);
                                return JobResult {
                                    job_id: req.job_id,
                                    status: JobStatus::Failed,
                                    output_payload: serde_json::json!({"error": err}),
                                    logs: vec![],
                                    execution_time_ms: start.elapsed().as_millis() as u64,
                                    signature: vec![],
                                    result_nonce: String::new(),
                                    worker_id: String::new(),
                                };
                            }
                            // H1: prefer the digest we already learned from
                            // the pre-pull manifest fetch (`expected_layer_digest`,
                            // captured in the outer scope). Falling back to the
                            // pull-response's `image.manifest.layers[0].digest`
                            // covers the (rare) path where the pre-fetch failed
                            // but the full pull succeeded; both shapes flow
                            // through the same `verify_oci_layer` check.
                            let pull_response_digest = image
                                .manifest
                                .as_ref()
                                .and_then(|m| m.layers.first())
                                .map(|d| d.digest.clone());
                            let effective_digest =
                                expected_layer_digest.clone().or(pull_response_digest);
                            match verify_oci_layer(&layer.data, effective_digest.as_deref()) {
                                LayerVerdict::Verified { digest } => {
                                    _span.set_attribute("oci_layer_digest", digest);
                                    _span.add_event("oci_pull_success");

                                    // Populate the Redis cache so the next pull of
                                    // this layer-digest short-circuits the registry
                                    // round-trip. TTL bounds growth — without it,
                                    // cache size scales monotonically with distinct
                                    // digests ever seen. Tag repoints produce new
                                    // digests and new cache entries; old entries
                                    // expire on their own TTL.
                                    //
                                    // SECURITY: only cache when both layers
                                    // of attestation passed in THIS pull —
                                    // sigstore signature AND layer digest.
                                    // The digest check is already a
                                    // precondition of this `Verified` arm;
                                    // the sigstore check is gated below.
                                    // Caching on a sigstore-Audit failure
                                    // would poison the cache so future
                                    // pulls bypass verification entirely
                                    // (cache hits short-circuit the OCI
                                    // path). Skipping the SET keeps the
                                    // bytes from being served to *other*
                                    // jobs while still honouring the
                                    // operator-chosen Audit-mode intent
                                    // for THIS execution.
                                    //
                                    // The cache write only happens when we
                                    // actually have a digest-keyed `redis_key`
                                    // (set above). Without one, there's no
                                    // canonical key for future re-verification —
                                    // skipping the write is correct.
                                    if sigstore_pass_in_this_run {
                                        if let Some(key) = redis_key.as_deref() {
                                            if let Some(redis_client) = runtime.redis_client() {
                                                if let Ok(mut conn) = redis_client
                                                    .get_multiplexed_async_connection()
                                                    .await
                                                {
                                                    let _: Result<(), _> = redis::cmd("SET")
                                                        .arg(key)
                                                        .arg(&layer.data)
                                                        .arg("EX")
                                                        .arg(OCI_CACHE_TTL_SECS)
                                                        .query_async(&mut conn)
                                                        .await;
                                                }
                                            }
                                        }
                                    } else {
                                        ::tracing::info!(
                                            module_uri = %req.module_uri,
                                            "OCI bytes attested by digest only \
                                             (sigstore failed in audit mode) — \
                                             skipping cache write so future pulls \
                                             re-verify against the registry"
                                        );
                                    }

                                    // Fresh pull with Sigstore + digest checks both
                                    // passed in THIS run — attested.
                                    bytes_attested_in_this_run = true;
                                    found_bytes = Some(layer.data);
                                }
                                LayerVerdict::DigestMismatch { expected, computed } => {
                                    let err = format!(
                                        "oci_digest_mismatch: manifest declared {}, computed {}",
                                        expected, computed
                                    );
                                    ::tracing::error!(
                                        module_uri = %req.module_uri,
                                        expected = %expected,
                                        computed = %computed,
                                        "OCI layer digest mismatch — refusing to execute"
                                    );
                                    _span.end_error(&err);
                                    return JobResult {
                                        job_id: req.job_id,
                                        status: JobStatus::Failed,
                                        output_payload: serde_json::json!({"error": err}),
                                        logs: vec![],
                                        execution_time_ms: start.elapsed().as_millis() as u64,
                                        signature: vec![],
                                        result_nonce: String::new(),
                                        worker_id: String::new(),
                                    };
                                }
                                LayerVerdict::AcceptedUnverified => {
                                    // M2 (2026-05-22): refuse to execute
                                    // bytes that lack a manifest layer
                                    // descriptor by default. Previously
                                    // accepted with a WARN; that meant a
                                    // compromised registry could serve a
                                    // malformed manifest with arbitrary
                                    // bytes and the worker would run them
                                    // (the sigstore + size caps still
                                    // ran, but no content-addressable
                                    // attestation tied the bytes to the
                                    // registry's claim about them).
                                    //
                                    // Operators with legacy registries
                                    // that genuinely produce manifests
                                    // without layer descriptors can set
                                    // `TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS=1`
                                    // to restore the old behaviour, at the
                                    // cost of accepting unverified bytes.
                                    //
                                    // H-5 (2026-05-23, wasm-security review):
                                    // the env var was a single-knob bypass
                                    // of the entire layer-digest gate. Even
                                    // with `TALOS_SIGSTORE_REQUIRED=required`
                                    // and `is_production() == true`, an
                                    // operator who toggled this on rendered
                                    // the integrity contract void with no
                                    // safety net. Defense-in-depth fix: the
                                    // env override is now refused whenever
                                    // Sigstore is `Required` OR the process
                                    // is in production. Operators on legacy
                                    // registries must downgrade Sigstore
                                    // policy AND/OR move out of production
                                    // mode to use it — making the trade-off
                                    // explicit rather than hiding it behind
                                    // one toggle.
                                    let accept_env =
                                        std::env::var("TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS")
                                            .ok()
                                            .as_deref()
                                            == Some("1");
                                    let prod = talos_config::is_production();
                                    let sigstore_required = matches!(
                                        SigstorePolicy::from_env(),
                                        SigstorePolicy::Required
                                    );
                                    if accept_env && !prod && !sigstore_required {
                                        ::tracing::warn!(
                                            module_uri = %req.module_uri,
                                            "OCI manifest had no layer descriptor — \
                                             accepting bytes unverified \
                                             (TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS=1, \
                                             dev mode, sigstore not Required)"
                                        );
                                        _span.add_event("oci_pull_success_unverified");
                                        found_bytes = Some(layer.data);
                                    } else {
                                        let err = if accept_env && (prod || sigstore_required) {
                                            // Operator tried to use the bypass in an
                                            // environment that disallows it — call out
                                            // the conflict explicitly so the operator
                                            // can choose to downgrade Sigstore policy
                                            // or move out of production mode if the
                                            // legacy-registry path is genuinely needed.
                                            ::tracing::error!(
                                                module_uri = %req.module_uri,
                                                prod, sigstore_required,
                                                "OCI manifest had no layer descriptor AND \
                                                 TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS=1 was \
                                                 set in a stricter context — refusing the bypass"
                                            );
                                            "oci_manifest_missing_layer_descriptor: \
                                         registry returned a manifest with no \
                                         layer digest. TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS=1 \
                                         is REFUSED in production and when sigstore \
                                         policy is Required — fix the registry or \
                                         relax both gates before using the bypass."
                                        } else {
                                            ::tracing::error!(
                                                module_uri = %req.module_uri,
                                                "OCI manifest had no layer descriptor — \
                                                 refusing to execute (M2 hardening)"
                                            );
                                            "oci_manifest_missing_layer_descriptor: \
                                         registry returned a manifest with no \
                                         layer digest — refusing to execute. Set \
                                         TALOS_OCI_ACCEPT_UNVERIFIED_MANIFESTS=1 \
                                         to allow legacy registries (dev only, \
                                         sigstore not Required)."
                                        };
                                        _span.end_error(err);
                                        return JobResult {
                                            job_id: req.job_id,
                                            status: JobStatus::Failed,
                                            output_payload: serde_json::json!({"error": err}),
                                            logs: vec![],
                                            execution_time_ms: start.elapsed().as_millis() as u64,
                                            signature: vec![],
                                            result_nonce: String::new(),
                                            worker_id: String::new(),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        ::tracing::warn!(module_uri = %req.module_uri, error = %e, "Failed to pull WASM artifact from OCI registry");
                        let err_msg = format!("oci_pull_error: {}", e);
                        let sanitized_error = sanitize_error_message(&err_msg);
                        _span.add_event(&sanitized_error);
                    }
                }
            } // end `if found_bytes.is_none()` cache-miss block
        }

        match found_bytes {
            Some(b) => b,
            None => {
                _span.end_error("WASM payload not found in OCI registry");
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": "WASM payload not found in OCI registry"}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
        }
    } else if req.module_uri.starts_with("redis:wasm:") {
        // Fetch from Redis via TalosRuntime's redis client
        _span.add_event("fetching_from_redis");

        let mut found_bytes: Option<Vec<u8>> = None;
        if let Some(redis_client) = runtime.redis_client() {
            if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                // remove "redis:" prefix to get the actual key: "wasm:{user_id}:{module_id}"
                let key = req
                    .module_uri
                    .strip_prefix("redis:")
                    .unwrap_or(&req.module_uri);
                if let Ok(Some(b)) = redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<Vec<u8>>>(&mut conn)
                    .await
                {
                    found_bytes = Some(b);
                }
            }
        }

        if let Some(b) = found_bytes {
            // H-3: cap also applies to the direct `redis:wasm:` path —
            // an attacker with Redis write access could plant an
            // oversized WASM blob here too. Reject before the bytes
            // reach wasmtime so the OOM defense applies uniformly
            // across all load sources.
            let layer_cap = max_oci_layer_bytes();
            if (b.len() as u64) > layer_cap {
                let err = format!(
                    "wasm_module_too_large: redis:wasm: blob is {} bytes, cap is {layer_cap}",
                    b.len()
                );
                ::tracing::error!(
                    module_uri = %req.module_uri,
                    blob_size = b.len(),
                    cap_bytes = layer_cap,
                    "redis:wasm: blob exceeds cap — refusing to execute"
                );
                _span.end_error(&err);
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({"error": err}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
            _span.set_attribute_int("module_size_bytes", b.len() as i64);
            _span.set_attribute("module_source", "redis");
            b
        } else {
            let error_msg =
                "failed to fetch wasm module from redis (not found or redis unavailable)";
            _span.set_attribute("error", error_msg);
            _span.end_error(error_msg);

            return JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}),
                logs: vec![],
                execution_time_ms: start.elapsed().as_millis() as u64,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            };
        }
    } else {
        // FALLBACK: Read from file system if bytes not provided
        match std::fs::read(&req.module_uri) {
            Ok(b) => {
                // H-3: cap applies to filesystem loads too. Even though
                // the controller would normally bound this via
                // `expected_wasm_hash` (set from `wasm_modules.content_hash`),
                // a malicious controller or compromised pod could
                // request a giant path. Reject loudly.
                let layer_cap = max_oci_layer_bytes();
                if (b.len() as u64) > layer_cap {
                    let err = format!(
                        "wasm_module_too_large: filesystem file is {} bytes, cap is {layer_cap}",
                        b.len()
                    );
                    ::tracing::error!(
                        module_uri = %req.module_uri,
                        file_size = b.len(),
                        cap_bytes = layer_cap,
                        "filesystem WASM exceeds cap — refusing to execute"
                    );
                    _span.end_error(&err);
                    return JobResult {
                        job_id: req.job_id,
                        status: JobStatus::Failed,
                        output_payload: serde_json::json!({"error": err}),
                        logs: vec![],
                        execution_time_ms: start.elapsed().as_millis() as u64,
                        signature: vec![],
                        result_nonce: String::new(),
                        worker_id: String::new(),
                    };
                }
                _span.set_attribute_int("module_size_bytes", b.len() as i64);
                _span.set_attribute("module_source", "filesystem");
                b
            }
            Err(e) => {
                let error_msg = format!("failed to read wasm module: {}", e);
                let sanitized_error = sanitize_error_message(&error_msg);
                _span.set_attribute("error", &sanitized_error);
                _span.end_error(&sanitized_error);

                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: json!({"error": sanitized_error}),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
        }
    };

    // SECURITY: Verify WASM content hash when inline bytes were not provided.
    // `req.expected_wasm_hash` is set by the controller from `wasm_modules.content_hash`
    // (the SHA-256 recorded at compile time) and covered by the HMAC signing payload,
    // so an attacker who compromises the storage layer (Redis, OCI, filesystem) cannot
    // substitute malicious bytes without the mismatch being detected here.
    //
    // When `wasm_bytes` was provided inline the HMAC already covers sha256(bytes) — no
    // additional check needed.  We only verify when the worker loaded bytes from a URI.
    if req.wasm_bytes.is_none() {
        if let Some(ref expected) = req.expected_wasm_hash {
            use sha2::{Digest, Sha256};
            let actual = hex::encode(Sha256::digest(&wasm_bytes));
            if actual != *expected {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    expected_hash = %expected,
                    actual_hash = %actual,
                    "SECURITY: WASM content hash mismatch — possible storage tampering, refusing execution"
                );
                _span.end_error("wasm_hash_mismatch");
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({
                        "error": "WASM integrity check failed: content hash mismatch"
                    }),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                hash = %actual,
                "WASM content hash verified"
            );
        } else if !bytes_attested_in_this_run {
            // No hash commitment from the controller AND the bytes did not
            // pass Sigstore + layer-digest checks in this run — i.e. they
            // came from an OCI cache fallback, `redis:wasm:` fetch, or
            // filesystem load with nothing cryptographically tying them
            // to the controller's recorded `wasm_modules.content_hash`.
            //
            // A Redis-write attacker (compromised pod, shared infra) could
            // substitute arbitrary WASM into the cache — without
            // `expected_wasm_hash` we have no evidence to detect it.
            //
            // M-5: gate this fallback on a POSITIVE opt-in
            // (`TALOS_ALLOW_UNATTESTED_WASM=1`) instead of "if not
            // production". Pre-fix a dev image accidentally promoted to
            // production, or a container with `RUST_ENV` unset, would
            // silently accept arbitrary cache bytes. The new policy is
            // fail-closed by default: misconfiguration refuses to run.
            // Operators who need the dev shortcut must set the env var
            // explicitly. The legacy production gate stays as
            // belt-and-braces — production never accepts unattested
            // bytes regardless of the override.
            let is_prod = talos_config::is_production();
            let allow_unattested = std::env::var("TALOS_ALLOW_UNATTESTED_WASM")
                .ok()
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            let block_unattested = is_prod || !allow_unattested;
            if block_unattested {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    "SECURITY: refusing to execute WASM loaded from unverified storage \
                     (cache/redis/filesystem) without expected_wasm_hash. Either supply \
                     a hash or load from a path that Sigstore-verifies in this run"
                );
                _span.end_error("unattested_wasm_no_hash");
                return JobResult {
                    job_id: req.job_id,
                    status: JobStatus::Failed,
                    output_payload: serde_json::json!({
                        "error": "WASM integrity check failed: no hash and no in-run attestation"
                    }),
                    logs: vec![],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    signature: vec![],
                    result_nonce: String::new(),
                    worker_id: String::new(),
                };
            }
            ::tracing::warn!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM loaded from unattested storage without expected_wasm_hash \
                 (TALOS_ALLOW_UNATTESTED_WASM=1 set — would fail closed without this override). \
                 Always supply expected_wasm_hash or attest in-run via Sigstore in production."
            );
        } else {
            // Bytes were attested in this run via Sigstore + digest checks.
            // No expected_wasm_hash supplied is OK — the in-run attestation
            // is the trust root.
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM attested via in-run Sigstore + layer-digest verification"
            );
        }
    }

    // Build execution context for automatic logging to database
    _span.add_event("executing_wasm");
    let execution_context = Some((
        req.workflow_execution_id.to_string(), // workflow_id
        req.job_id.to_string(),                // execution_id (for NATS logging)
        req.module_uri.clone(),                // module_id
    ));

    // Build per-module security policy from the job request.
    let security_policy = SecurityPolicy {
        allowed_secrets: req.allowed_secrets.clone(),
        allowed_sql_operations: req.allowed_sql_operations.clone(),
        allow_tier2_exposure: req.allow_tier2_exposure,
        integration_name: req.integration_name.clone(),
    };

    // Parse the capability world hint from the controller.  When present and non-Unknown,
    // the runtime uses it instead of re-inspecting the WASM binary.  This is critical for
    // sandbox modules whose Wizer-snapshotted binary may have lost embedded WIT world-name
    // strings that inspect_component relies on.
    let capability_world_hint: Option<crate::wit_inspector::CapabilityWorld> =
        req.capability_world.as_deref().and_then(|s| s.parse().ok());

    // Honor the controller-supplied `timeout_ms` from the job request. The
    // controller has already sourced it from the node's `timeout_secs` (or the
    // per-env `WASM_EXECUTION_TIMEOUT_SECS` default). Fallback: use the same
    // `WASM_EXECUTION_TIMEOUT_SECS` env var (60s default) when the request
    // didn't specify. Previously both timeouts were hardcoded 30s, which
    // silently capped agent-node modules calling `llm::complete` even when
    // the author set `timeout_secs: 120` on the node.
    // MCP-642 (2026-05-13): if WASM_EXECUTION_TIMEOUT_SECS=0 AND the
    // caller didn't specify req.timeout_ms, the job timeout below
    // becomes 0ms → every job times out instantly. Same MCP-639 class.
    let worker_fallback_secs: u64 =
        crate::runtime::nonzero_env_or_default("WASM_EXECUTION_TIMEOUT_SECS", 60);
    let job_timeout_ms: u64 = if req.timeout_ms > 0 {
        req.timeout_ms
    } else {
        worker_fallback_secs.saturating_mul(1000)
    };
    let job_timeout = std::time::Duration::from_millis(job_timeout_ms);
    match tokio::time::timeout(
        job_timeout,
        runtime.execute_job_with_full_features(
            &wasm_bytes,
            req.allowed_hosts.clone(),
            req.allowed_methods.clone(),
            128,
            req.input_payload.clone(),
            None, // No custom file sandbox
            execution_context,
            secrets,
            None,        // token_sender
            job_timeout, // per-job timeout — matches the outer tokio::time::timeout
            RetryPolicy::default(),
            None, // No result caching for NATS jobs — each execution must be fresh
            security_policy,
            capability_world_hint,
            if req.max_fuel > 0 {
                Some(req.max_fuel)
            } else {
                None
            },
            req.dry_run,
            req.actor_id,
            req.user_id,
            req.max_llm_tier,
        ),
    )
    .await
    {
        Ok(Ok(output)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_success();

            JobResult {
                job_id: req.job_id,
                status: JobStatus::Success,
                output_payload: output,
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Ok(Err(e)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("execution failure: {}", e);
            let sanitized_error = sanitize_error_message(&error_msg);
            _span.set_attribute("error", &sanitized_error);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&sanitized_error);

            JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": sanitized_error}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Err(_) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = "execution timed out after 30 seconds".to_string();
            _span.set_attribute("error", &error_msg);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&error_msg);

            JobResult {
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
    }
}

/// Execute a pipeline job dispatched via NATS.
///
/// * Verifies the HMAC signature and nonce freshness.
/// * Decrypts per-step secrets.
/// * Runs `execute_pipeline()` on the runtime.
/// * Signs and publishes the `PipelineJobResult`.
#[::tracing::instrument(name = "pipeline-execution", skip_all)]
async fn execute_pipeline_job(
    cx: &opentelemetry::Context,
    req: PipelineJobRequest,
    runtime: Arc<TalosRuntime>,
    shared_key: talos_workflow_engine_core::WorkerKeyRing,
) -> PipelineJobResult {
    use talos_workflow_job_protocol::JobStatus;

    let start = std::time::Instant::now();
    // The `#[instrument]` span above is THE pipeline span; wrap + link it to the
    // propagated controller trace context (see `execute_job` for the rationale).
    let mut _span = JobSpan::current_with_parent(cx);

    // SECURITY: Verify HMAC-SHA256 signature + nonce freshness (300 s window).
    // Ring-aware (current OR staged previous key) for rolling rotation.
    if let Err(e) = req.verify_with_ring(&shared_key, 300) {
        ::tracing::error!(job_id = %req.job_id, error = %e, "Pipeline job signature verification failed");
        _span.set_attribute("error", "signature_verification_failed");
        _span.end_error("Signature verification failed");
        return PipelineJobResult {
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": "pipeline signature verification failed"}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // Validate maximum pipeline timeout to prevent indefinitely tying up workers.
    // MCP-642: =0 would reject every pipeline job (req.total_timeout_ms > 0
    // always exceeds 0). Substitute default + WARN.
    let max_timeout_ms: u64 =
        crate::runtime::nonzero_env_or_default("WASM_MAX_PIPELINE_TIMEOUT_MS", 3_600_000);

    if req.total_timeout_ms > max_timeout_ms {
        ::tracing::warn!(
            job_id = %req.job_id,
            requested_ms = req.total_timeout_ms,
            max_ms = max_timeout_ms,
            "Pipeline job rejected: timeout exceeds maximum"
        );
        _span.end_error("Timeout exceeds maximum");
        return PipelineJobResult {
            job_id: req.job_id,
            overall_status: JobStatus::Failed,
            step_results: vec![],
            final_output: serde_json::json!({"error": format!("Requested total timeout ({}ms) exceeds maximum allowed ({}ms)", req.total_timeout_ms, max_timeout_ms)}),
            total_time_ms: start.elapsed().as_millis() as u64,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
    }

    // Build PipelineStepSpecs by decrypting per-step secrets.
    // L-1: AAD = workflow_execution_id, shared across all steps in
    // this pipeline (matches the encryption-side binding).
    let mut step_specs: Vec<PipelineStepSpec> = Vec::with_capacity(req.steps.len());
    for step in &req.steps {
        let secrets = if step.encrypted_secrets.is_empty() {
            std::collections::HashMap::new()
        } else {
            match step
                .encrypted_secrets
                .decrypt_with_ring(&shared_key, req.workflow_execution_id.as_bytes())
            {
                Ok(s) => s,
                Err(e) => {
                    ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt pipeline step secrets");
                    _span.end_error("Secret decryption failed");
                    return PipelineJobResult {
                        job_id: req.job_id,
                        overall_status: JobStatus::Failed,
                        step_results: vec![],
                        final_output: serde_json::json!({"error": "failed to decrypt step secrets"}),
                        total_time_ms: start.elapsed().as_millis() as u64,
                        signature: vec![],
                        result_nonce: String::new(),
                        worker_id: String::new(),
                    };
                }
            }
        };

        step_specs.push(PipelineStepSpec {
            module_id: step.module_id.to_string(),
            wasm_bytes: step.wasm_bytes.clone().unwrap_or_default(),
            config: step.config.clone(),
            allowed_hosts: step.allowed_hosts.clone(),
            allowed_methods: step.allowed_methods.clone(),
            secrets,
            max_fuel: step.max_fuel,
            max_memory_mb: step.max_memory_mb,
            timeout: std::time::Duration::from_millis(step.timeout_ms),
            security_policy: SecurityPolicy {
                allowed_secrets: step.allowed_secrets.clone(),
                allowed_sql_operations: step.allowed_sql_operations.clone(),
                allow_tier2_exposure: step.allow_tier2_exposure,
                integration_name: step.integration_name.clone(),
            },
            user_id: Some(req.user_id),
        });
    }

    let overall_timeout = std::time::Duration::from_millis(req.total_timeout_ms);

    match runtime
        .execute_pipeline(
            &req.workflow_execution_id.to_string(),
            step_specs,
            overall_timeout,
            req.share_sandbox,
            req.max_llm_tier,
        )
        .await
    {
        Ok(pipeline_result) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", total_time_ms as i64);
            _span.end_success();

            let step_results: Vec<PipelineStepResult> = req
                .steps
                .iter()
                .zip(pipeline_result.step_outputs.iter())
                .zip(pipeline_result.step_times_ms.iter())
                .map(|((step, output), &time_ms)| PipelineStepResult {
                    module_id: step.module_id,
                    status: JobStatus::Success,
                    output: output.clone(),
                    execution_time_ms: time_ms,
                    error: None,
                })
                .collect();

            PipelineJobResult {
                job_id: req.job_id,
                overall_status: JobStatus::Success,
                step_results,
                final_output: pipeline_result.final_output,
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
        Err(e) => {
            let total_time_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("pipeline execution failure: {}", e);
            let sanitized_error = sanitize_error_message(&error_msg);
            _span.set_attribute("error", &sanitized_error);
            _span.set_attribute_int("duration_ms", total_time_ms as i64);
            _span.end_error(&sanitized_error);

            PipelineJobResult {
                job_id: req.job_id,
                overall_status: JobStatus::Failed,
                step_results: vec![],
                final_output: serde_json::json!({"error": sanitized_error}),
                total_time_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires an explicit CryptoProvider when the dep graph
    // contains more than one. We pull rustls in via redis (tls-rustls) and
    // reqwest. install_default is idempotent — Err means another caller
    // already installed one, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("=== Talos Worker Starting ===\n");

    // ========================================================================
    // SECURITY: Load and validate the shared key at startup.
    // Fail-fast if the key is absent or malformed — never start with no auth.
    // ========================================================================

    // Load the full verify/decrypt-ring (current + WORKER_SHARED_KEY_PREVIOUS).
    // The worker SIGNS results + RPC with the current key only; it VERIFIES
    // controller-signed jobs and DECRYPTS secrets against the whole ring, so a
    // rolling WORKER_SHARED_KEY rotation doesn't break either side mid-roll.
    let shared_key =
        load_worker_key_ring().map_err(|e| anyhow::anyhow!("WORKER_SHARED_KEY error: {}", e))?;
    // M-3 (partial): log a SHA-256 fingerprint of the shared key at
    // startup so config drift between controller and worker is visible
    // without exposing the key material. Operators can grep both
    // process logs for `worker_shared_key_fp=` and confirm they match
    // — if they don't, all signed RPCs will fail verification and the
    // error surfaces here instead of as opaque "signature verification
    // failed" later. We log only the first 8 hex chars (32 bits) which
    // is enough to detect mismatch with negligible info leak.
    {
        let fp_short = talos_workflow_job_protocol::worker_key_fingerprint(
            shared_key.signing_key().as_bytes(),
        );
        let verify_count = shared_key.verify_keys().len();
        println!(
            "[0/5] Loaded WORKER_SHARED_KEY (32 bytes, fp={fp_short}, verify_keys={verify_count})"
        );
        ::tracing::info!(
            worker_shared_key_fp = %fp_short,
            verify_key_count = verify_count,
            "WORKER_SHARED_KEY loaded; compare this fingerprint against the controller's log line for drift detection"
        );
        for prev in shared_key.verify_keys().iter().skip(1) {
            ::tracing::info!(
                previous_worker_shared_key_fp =
                    %talos_workflow_job_protocol::worker_key_fingerprint(prev.as_bytes()),
                "WORKER_SHARED_KEY_PREVIOUS accepted for verify/decrypt (rotation in progress)"
            );
        }
    }

    // Wasm-security review 2026-05-22 (MEDIUM-4): production gate. In
    // production we refuse to boot unless the operator has made an
    // explicit Sigstore choice (required / audit / disabled). Pre-fix,
    // `from_env` silently fell through to `Disabled` when the env var
    // was unset — the operator's monitoring saw a clean startup and
    // had no signal that signature verification was off. Mirrors the
    // `TALOS_AOT_HMAC_KEY` boot discipline so production failures are
    // loud and immediate. Dev/test hosts (`is_production() == false`)
    // continue to see the silent default.
    enforce_production_sigstore_policy_explicit()?;

    // L-4: Sigstore startup sanity — verify `cosign` is actually
    // executable when policy is non-Disabled. Pre-fix the missing
    // binary surfaced as a per-pull "cosign_unavailable" error;
    // production deploys that THOUGHT verification was running
    // discovered the gap only when an unsigned artifact slipped
    // through (or, in Required mode, when every pull failed).
    // Failing at boot in Required mode is loud, immediate, and
    // points at the right config knob.
    {
        let sigstore_policy = SigstorePolicy::from_env();
        if sigstore_policy != SigstorePolicy::Disabled {
            match tokio::process::Command::new("cosign")
                .arg("version")
                .output()
                .await
            {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let version_line = stdout.lines().next().unwrap_or("(unknown)").to_string();

                    // M5 (2026-05-22): version-pin cosign so a swapped-in
                    // older binary (predating critical CVE fixes) or a
                    // replaced binary doesn't silently pass through.
                    // `TALOS_COSIGN_MIN_VERSION` is the minimum
                    // semver-ish version accepted; default `2.0.0`
                    // matches the cosign 2.x line which is the
                    // long-supported branch with hardened defaults.
                    //
                    // Parse rule: pull the first dotted `X.Y.Z` token
                    // out of stdout (cosign output format has shifted
                    // across versions; the version triple is the only
                    // stable shape). Fail-closed in Required mode if
                    // we can't parse anything; warn-and-continue under
                    // Audit. This is operator-tunable via the env so
                    // a future cosign 3.x bump doesn't require code
                    // changes.
                    let min_version = std::env::var("TALOS_COSIGN_MIN_VERSION")
                        .ok()
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "2.0.0".to_string());
                    match parse_cosign_version(&stdout) {
                        Some((maj, min, patch)) => {
                            let parsed_observed = (maj, min, patch);
                            let parsed_min = parse_semver_triple(&min_version).unwrap_or((2, 0, 0));
                            if parsed_observed < parsed_min {
                                let msg = format!(
                                    "cosign version {}.{}.{} is below required minimum {} \
                                     (set TALOS_COSIGN_MIN_VERSION to override)",
                                    parsed_observed.0,
                                    parsed_observed.1,
                                    parsed_observed.2,
                                    min_version,
                                );
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Sigstore startup sanity check failed: {msg}"
                                    ));
                                }
                                ::tracing::warn!(
                                    cosign_version = %version_line,
                                    min_version = %min_version,
                                    "{msg} (Audit mode: continuing)"
                                );
                            }
                        }
                        None => {
                            if sigstore_policy == SigstorePolicy::Required {
                                return Err(anyhow::anyhow!(
                                    "Could not parse cosign version from stdout: {version_line:?}. \
                                     Required policy refuses to boot without a verified version pin."
                                ));
                            }
                            ::tracing::warn!(
                                stdout = %stdout,
                                "Could not parse cosign version — version-pin check skipped (Audit mode)"
                            );
                        }
                    }

                    // M5 part B: optional SHA-256 pin of the cosign
                    // binary itself. When set, the worker hashes the
                    // resolved cosign executable and refuses to boot
                    // if the hash doesn't match. This closes the
                    // "swap cosign with a wrapper that always exits 0"
                    // attack path. Most operators won't set this;
                    // sigstore-enforcement clusters that want defense
                    // in depth absolutely should.
                    //
                    // L-3 (2026-05-22): under Required policy, advise
                    // operators who run WITHOUT a hash pin that an
                    // attacker with worker-pod write access (sidecar
                    // exploit, init-container compromise) can swap the
                    // cosign binary for a wrapper that always exits 0 —
                    // bypassing every other Sigstore gate. Loud WARN at
                    // startup so the gap is visible in production logs;
                    // not fail-closed because Required-without-pin is a
                    // legitimate (if weaker) deployment posture and the
                    // pin requires per-image hash bookkeeping operators
                    // may roll out separately from this code change.
                    let cosign_pin = std::env::var("TALOS_COSIGN_SHA256")
                        .ok()
                        .filter(|v| !v.is_empty());
                    if cosign_pin.is_none() && sigstore_policy == SigstorePolicy::Required {
                        ::tracing::warn!(
                            policy = ?sigstore_policy,
                            "TALOS_COSIGN_SHA256 not set under Required Sigstore policy — \
                             cosign binary will not be hash-verified at startup. Set \
                             TALOS_COSIGN_SHA256 to the sha256 of the bundled cosign \
                             binary for defense-in-depth against binary-swap attacks."
                        );
                    }
                    if let Some(expected_sha256) = cosign_pin {
                        match resolve_and_hash_cosign_binary().await {
                            Ok(actual) => {
                                use subtle::ConstantTimeEq as _;
                                let actual_lower = actual.to_lowercase();
                                let expected_lower = expected_sha256.trim().to_lowercase();
                                let eq: bool = actual_lower
                                    .as_bytes()
                                    .ct_eq(expected_lower.as_bytes())
                                    .into();
                                if !eq {
                                    if sigstore_policy == SigstorePolicy::Required {
                                        return Err(anyhow::anyhow!(
                                            "cosign binary sha256 mismatch: expected {expected_lower}, \
                                             got {actual_lower}. Required policy refuses to boot."
                                        ));
                                    }
                                    ::tracing::warn!(
                                        expected = %expected_lower,
                                        actual = %actual_lower,
                                        "cosign binary sha256 mismatch (Audit mode: continuing)"
                                    );
                                } else {
                                    ::tracing::info!(
                                        sha256 = %actual_lower,
                                        "cosign binary sha256 pin verified"
                                    );
                                }
                            }
                            Err(e) => {
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Could not hash cosign binary for SHA-256 pin: {e}. \
                                         Required policy refuses to boot."
                                    ));
                                }
                                ::tracing::warn!(
                                    error = %e,
                                    "Could not hash cosign binary — sha256 pin check skipped (Audit mode)"
                                );
                            }
                        }
                    }

                    ::tracing::info!(
                        cosign_version = %version_line,
                        policy = ?sigstore_policy,
                        "Sigstore startup sanity check: cosign binary OK"
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary present but `cosign version` exited non-zero (stderr: {stderr}). \
                             Required policy refuses to boot."
                        ));
                    }
                    ::tracing::warn!(
                        stderr = %stderr,
                        "Sigstore startup sanity check: cosign returned non-zero — verifications will fail"
                    );
                }
                Err(e) => {
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary not executable ({e}) and Sigstore policy is Required. \
                             Install cosign in the worker image or set TALOS_SIGSTORE_REQUIRED=audit \
                             during migration."
                        ));
                    }
                    ::tracing::warn!(
                        error = %e,
                        "Sigstore startup sanity check: cosign not executable — Audit mode will warn-and-continue on every pull"
                    );
                }
            }
        }
    }

    // M-1: validate Sigstore identity regexp at startup so an operator
    // who set `TALOS_SIGSTORE_REQUIRED=true` with a permissive pattern
    // discovers the policy is broken HERE — not silently per-pull when
    // every malicious-signature artifact passes verification. In
    // `Required` mode any rejection is fatal; in `Audit` mode we WARN
    // and continue (audit is the migration window). `Disabled` mode
    // skips this entirely.
    {
        let sigstore_policy_at_startup = SigstorePolicy::from_env();
        if sigstore_policy_at_startup != SigstorePolicy::Disabled {
            let regexp = std::env::var("TALOS_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
            match validate_sigstore_identity_regexp(&regexp) {
                Ok(()) => {
                    ::tracing::info!(
                        policy = ?sigstore_policy_at_startup,
                        "Sigstore identity regexp validated at startup"
                    );
                }
                Err(rejection) => match sigstore_policy_at_startup {
                    SigstorePolicy::Required => {
                        return Err(anyhow::anyhow!(
                            "TALOS_SIGSTORE_IDENTITY_REGEXP rejected at startup ({:?}): {}. \
                             Fix the env var and restart — \
                             refusing to run under Required policy with broken config.",
                            rejection,
                            rejection.human_reason()
                        ));
                    }
                    SigstorePolicy::Audit => {
                        ::tracing::warn!(
                            rejection = ?rejection,
                            reason = %rejection.human_reason(),
                            "TALOS_SIGSTORE_IDENTITY_REGEXP rejected under Audit policy — \
                             would fail closed under Required"
                        );
                    }
                    SigstorePolicy::Disabled => unreachable!(),
                },
            }
        }
    }

    // Install the same key into talos-memory's RPC auth slot so the
    // WIT `agent_memory::*` and `graph_memory::*` host functions can
    // sign their NATS requests. The controller registers the same
    // key on its side for verification (see controller/src/main.rs).
    // Worker only SIGNS its outbound RPC (controller verifies), so the
    // current/signing key is all rpc_auth needs here.
    talos_memory::rpc_auth::register_hmac_key(Arc::new(
        shared_key.signing_key().as_bytes().to_vec(),
    ));

    // M-3 (2026-05-22): log the SQL empty-allowlist policy at startup
    // so operators can confirm the mode they're running. Default is
    // `DenyMutations` (least-privilege); `AllowAllNonDdl` is the
    // legacy permissive mode reachable via
    // `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. Logged at INFO so it
    // appears once at boot without spamming normal traffic.
    {
        let sql_policy = sql_validator::EmptyAllowlistPolicy::from_env();
        match sql_policy {
            sql_validator::EmptyAllowlistPolicy::DenyMutations => {
                ::tracing::info!(
                    policy = "DenyMutations",
                    "SQL validator: empty allowlist permits SELECT/EXPLAIN only (default)"
                );
            }
            sql_validator::EmptyAllowlistPolicy::AllowAllNonDdl => {
                ::tracing::warn!(
                    policy = "AllowAllNonDdl",
                    "SQL validator: legacy permissive mode is enabled via \
                     TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST — JobRequests with empty \
                     allowed_sql_operations admit every non-DDL non-AlwaysBlocked \
                     statement type. Prefer setting allowed_sql_operations explicitly."
                );
            }
        }
    }

    // ========================================================================
    // OBSERVABILITY INITIALIZATION
    // ========================================================================

    println!("[1/5] Initializing observability...");

    if let Err(e) = metrics::init_telemetry() {
        eprintln!("Warning: Failed to initialize metrics: {}", e);
        eprintln!("    Continuing without metrics...");
    } else {
        println!("      Metrics initialized");
    }

    // Initialise OTel tracing FIRST — `init_tracing` installs the SDK provider
    // (+ the W3C propagator used by `extract_trace_context`). The otel bridge
    // layer in the subscriber below pulls a tracer from that provider, so the
    // provider must exist before the subscriber is built.
    let jaeger_endpoint = std::env::var("JAEGER_ENDPOINT")
        .ok()
        .or_else(|| Some("http://localhost:4317".to_string()));

    if let Some(endpoint) = jaeger_endpoint.as_ref() {
        match tracing::init_tracing("talos-worker", Some(endpoint)) {
            Ok(_) => println!("      Tracing initialized (endpoint: {})", endpoint),
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracing: {}", e);
                eprintln!("    Continuing without tracing...");
            }
        }
    }

    // Install the tracing subscriber. The fmt layer keeps host_impl.rs
    // `tracing::warn!`/`info!` (security checks, vault allowlist, SSRF blocks,
    // rate limits) in `docker logs` (RUST_LOG, default: worker=info,warn). The
    // optional OTel bridge layer — present only when `init_tracing` installed a
    // provider above (OTLP endpoint configured) — exports the worker's `tracing`
    // spans to OTLP so each `job-execution` span (and the host-function spans
    // nested under it) appears in the trace backend, linked to the controller's
    // `workflow` span via the propagated context.
    //
    // PERF: the worker is the hot WASM-execution path. Span volume is bounded by
    // the global EnvFilter (info/warn) AND the otel sampler: the SDK default is
    // ParentBased(AlwaysOn), so jobs that carry a sampled controller context
    // inherit its decision; root jobs (e.g. module-bound gmail/gcal dispatch with
    // no controller span) sample at AlwaysOn. High-throughput deployments should
    // configure a ratio sampler on the controller (the parent) to bound export.
    {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("worker=info,warn"));
        let otel_layer = tracing::sdk_tracer("talos-worker")
            .map(|tracer| tracing_opentelemetry::layer().with_tracer(tracer));
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(false))
            .with(otel_layer)
            .init();
    }

    // MCP-580: spawn the circuit-breaker periodic cleanup task so the
    // per-host `records` DashMap doesn't grow monotonically with
    // distinct hosts seen across the worker's lifetime. Idempotent at
    // the breaker level (only Closed stale entries get evicted; Open /
    // HalfOpen are preserved). Pre-fix the cleanup() method existed
    // but had zero callers.
    circuit_breaker::spawn_periodic_cleanup();

    // FU-2 (R2-5): periodically sweep the job-idempotency cache so expired
    // completed-result entries don't linger on a worker that goes idle.
    // Read-path eviction handles active job_ids; this is the companion sweep
    // (CLAUDE.md cache rule: TTL cache = read-path eviction + periodic sweep).
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(
            crate::job_idempotency::SWEEP_INTERVAL_SECS,
        ));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            crate::job_idempotency::JOB_RESULT_CACHE.sweep();
            crate::job_idempotency::PIPELINE_PAYLOAD_CACHE.sweep();
        }
    });

    // ========================================================================
    // NATS CONNECTION
    // ========================================================================

    println!("\n[2/5] Connecting to NATS...");
    // MCP-631: empty-env hardening — `NATS_URL=""` (Helm placeholder)
    // would otherwise produce an empty URL and NATS connect fails with
    // a confusing parse error rather than using the default.
    let nats_url = std::env::var("NATS_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());

    // Sanitize the URL for logging — strip embedded credentials (nats://user:pass@host).
    let nats_url_safe = {
        let mut u = nats_url.clone();
        if let Some(at) = u.find('@') {
            let scheme_end = u.find("://").map(|i| i + 3).unwrap_or(0);
            u.replace_range(scheme_end..at + 1, "[credentials]@");
        }
        u
    };

    // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
    // MCP-631: empty-env hardening — pre-fix, `NATS_USER=""` +
    // `NATS_PASSWORD=""` (Helm placeholder) produced
    // `(Some(""), Some(""))` which matched the authenticated branch
    // BELOW, BYPASSING the production-mode auth gate. The worker
    // would then attempt to authenticate with empty credentials; if
    // the NATS server happened to allow anonymous connections (no
    // auth file), the worker would silently connect anonymously
    // despite the operator's intent. Treating empty as unset routes
    // the request through the unauthenticated branch where the
    // production gate refuses it. Sibling to MCP-590/591/592 family.
    let nats_user = std::env::var("NATS_USER").ok().filter(|v| !v.is_empty());
    let nats_password = std::env::var("NATS_PASSWORD")
        .ok()
        .filter(|v| !v.is_empty());
    // MCP-668 (2026-05-13): route through `talos_config::is_production()` so
    // a helm-rendered empty `RUST_ENV=""` doesn't bypass this gate. Raw
    // `unwrap_or_default()` produced `""` which !== `"production"`, allowing
    // the worker to fall through to unauthenticated NATS even in prod.
    // Same empty-env-var family as MCP-590/591/592/630/631 and the
    // MCP-653 RUST_ENV long-tail closure.
    let is_production = talos_config::is_production();

    let nc: Client = match (nats_user, nats_password) {
        (Some(user), Some(pass)) => {
            // apply_nats_ca adds the in-cluster NATS CA + requires TLS when
            // NATS_CA_FILE is set (tls:// URL); no-op otherwise.
            let opts = async_nats::ConnectOptions::new().user_and_password(user, pass);
            match talos_nats_tls::apply_nats_ca(opts).connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (authenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Check NATS_USER/NATS_PASSWORD credentials.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
        _ => {
            // SECURITY: In production, require NATS authentication to prevent
            // unauthorized job submission and message interception.
            if is_production {
                eprintln!("CRITICAL SECURITY ERROR: NATS_USER and NATS_PASSWORD must be set in production.");
                eprintln!(
                    "   Unauthenticated NATS connections are not allowed in production mode."
                );
                return Err(anyhow::anyhow!(
                    "NATS authentication required in production (set NATS_USER and NATS_PASSWORD)"
                ));
            }
            ::tracing::warn!(
                "NATS_USER/NATS_PASSWORD not set — connecting without authentication. \
                 This is acceptable for development but MUST NOT be used in production."
            );
            let opts = talos_nats_tls::apply_nats_ca(async_nats::ConnectOptions::new());
            match opts.connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (unauthenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Make sure a NATS server is running.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
    };

    // Retrieve configurable NATS queue topics or use defaults.
    // This enables per-customer VPC "Edge Node" routing.
    // MCP-631: empty-env hardening — empty NATS topic would silently
    // subscribe to "" which behaves as an unsubscribed topic and the
    // worker would receive no jobs without a loud error.
    let single_job_topic = std::env::var("NATS_JOB_TOPIC")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "talos.jobs".to_string());
    let pipeline_job_topic = std::env::var("NATS_PIPELINE_TOPIC")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "talos.pipeline.jobs".to_string());
    // Use the topic names as the queue groups so multiple edge nodes on the same topic load-balance
    let queue_group = single_job_topic.clone();
    let pipeline_queue_group = pipeline_job_topic.clone();

    let mut sub: Subscriber = nc
        .queue_subscribe(single_job_topic.clone(), queue_group.clone())
        .await?;
    println!(
        "      Subscribed to '{}' queue (group: {})",
        single_job_topic, queue_group
    );

    let mut pipeline_sub: Subscriber = nc
        .queue_subscribe(pipeline_job_topic.clone(), pipeline_queue_group.clone())
        .await?;
    println!(
        "      Subscribed to '{}' queue (group: {})",
        pipeline_job_topic, pipeline_queue_group
    );

    // ========================================================================
    // RUNTIME INITIALIZATION (with NATS client for logging)
    // ========================================================================

    // ========================================================================
    // REDIS CONNECTION (Phase 1: Decoupled Read Path)
    // ========================================================================

    println!("\n[2.5/5] Connecting to Redis...");
    let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        // SECURITY: Require TLS (rediss://) in production to prevent credential
        // and data interception on the network.
        if is_production && !redis_url.starts_with("rediss://") {
            eprintln!("FATAL: REDIS_URL must use rediss:// (TLS) in production");
            std::process::exit(1);
        }
        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => {
                // Test connection
                match client.get_multiplexed_async_connection().await {
                    Ok(_) => {
                        println!(
                            "      Connected to Redis at {}",
                            redis_url.split('@').next_back().unwrap_or("redis")
                        );
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to connect to Redis: {}. WASM cache interface will be unavailable.", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to create Redis client: {}. WASM cache interface will be unavailable.", e);
                None
            }
        }
    } else {
        println!("      REDIS_URL not configured. WASM cache interface will be unavailable.");
        None
    };

    // PostgreSQL connection block removed Phase 2.10. Worker is now
    // credential-free: the WIT `database::execute_query` host
    // function dispatches via signed NATS-RPC to the controller
    // (Phase 2.3). DATABASE_URL is intentionally not read here.

    println!("\n[3/5] Creating WASM runtime...");
    let runtime = Arc::new(TalosRuntime::with_resources(
        redis_client.clone(),       // Redis client for WASM fetching and caching
        Some(Arc::new(nc.clone())), // NATS client for WASM log publishing
        None,                       // No file system sandbox for now
    )?);
    println!("      Runtime created with NATS logging enabled (worker is credential-free; database access via NATS-RPC)");

    // M1 (2026-05-22): start the epoch-interruption ticker. Wasmtime
    // checks the engine's epoch counter at every loop backedge and
    // function entry; without a ticker the counter never advances and
    // the per-Store `set_epoch_deadline(N)` calls below would either
    // (a) never trip (deadline always in the future) or (b) trip at
    // the first yield (deadline == current epoch == 0). The ticker
    // gives the worker a third independent kill switch alongside fuel
    // + tokio wall-clock timeout. Cheap (one atomic increment per
    // EPOCH_TICK_INTERVAL_MS) and the JoinHandle is dropped so the
    // task runs for the lifetime of the process.
    let _epoch_ticker_handle = crate::runtime::spawn_epoch_ticker(runtime.engine_handle());
    println!("      Epoch-interruption ticker started (third kill switch alongside fuel + wall-clock timeout)");

    // ========================================================================
    // METRICS SERVER
    // ========================================================================

    println!("\n[4/5] Starting metrics server...");
    let metrics_port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9090);

    let _metrics_handle = metrics_server::start_metrics_server(runtime.clone(), metrics_port)
        .expect("Failed to start metrics server — ensure METRICS_AUTH_TOKENS is set");

    println!("      Metrics server running on port {}", metrics_port);
    println!(
        "         - Metrics: http://localhost:{}/metrics",
        metrics_port
    );
    println!(
        "         - Health:  http://localhost:{}/health",
        metrics_port
    );

    // ========================================================================
    // JOB PROCESSING LOOP
    // ========================================================================

    println!("\n[5/5] Starting job processing...");
    println!("\n=== Worker Ready ===");
    println!(
        "Listening for jobs on {} (queue: {})",
        nats_url, single_job_topic
    );

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_JOBS));
    let pipeline_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PIPELINE_JOBS));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Single-node jobs task ─────────────────────────────────────────────
    let single_nc = nc.clone();
    let single_runtime = runtime.clone();
    let single_key = shared_key.clone();
    let single_sem = semaphore.clone();
    let mut single_shutdown = shutdown_rx.clone();

    let single_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = single_shutdown.changed() => break,
                permit_res = single_sem.clone().acquire_owned() => {
                    let permit = match permit_res {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    tokio::select! {
                        _ = single_shutdown.changed() => break,
                        msg_opt = sub.next() => {
                            let msg = match msg_opt {
                                Some(m) => m,
                                None => break,
                            };

                            let cx = if let Some(ref headers) = msg.headers {
                                crate::trace_nats::extract_trace_context(headers)
                            } else {
                                opentelemetry::Context::new()
                            };

                            // SECURITY: cap payload size before deserialization to prevent
                            // memory exhaustion from oversized NATS messages.
                            const MAX_JOB_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB
                            if msg.payload.len() > MAX_JOB_PAYLOAD_BYTES {
                                ::tracing::error!(
                                    payload_bytes = msg.payload.len(),
                                    "SECURITY: rejecting oversized job payload"
                                );
                                continue;
                            }
                            let req: JobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    ::tracing::error!(error = %e, "Failed to decode job request");
                                    continue;
                                }
                            };

                            ::tracing::info!(job_id = %req.job_id, module_uri = %req.module_uri, "Received job");

                            let nc_clone = single_nc.clone();
                            let runtime_clone = single_runtime.clone();
                            let key_clone = single_key.clone();
                            let wire_reply = msg.reply.map(|r: async_nats::Subject| r.to_string());
                            // H-1: prefer the HMAC-bound `req.reply_topic`
                            // over the unsigned wire `msg.reply`. See
                            // `pick_trusted_reply_topic` for the matrix.
                            let reply_to = pick_trusted_reply_topic(
                                req.job_id,
                                req.reply_topic.as_deref(),
                                wire_reply.as_deref(),
                            );

                            tokio::task::spawn(async move {
                                // FU-2 (R2-5) idempotency: a controller transport-retry re-sends
                                // the same job_id (with a fresh nonce) AFTER the original
                                // executed. Re-publish the cached signed result instead of
                                // re-running the module (which would repeat side effects). The
                                // cached result is still within the 300s JobResult freshness
                                // window, so it's re-published as-is. dry_run jobs are never
                                // cached (no side effects, cheap to re-run).
                                if !req.dry_run {
                                    if let Some(cached) =
                                        crate::job_idempotency::JOB_RESULT_CACHE.get(req.job_id)
                                    {
                                        ::tracing::info!(
                                            job_id = %req.job_id,
                                            "idempotency: re-publishing cached result for re-seen \
                                             job_id (transport retry); skipping re-execution"
                                        );
                                        if let Err(e) = publish_result_with_retry(
                                            &nc_clone, &cached, 3, reply_to, &key_clone,
                                        )
                                        .await
                                        {
                                            ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to publish cached job result");
                                        }
                                        drop(permit);
                                        return;
                                    }
                                }

                                let mut result = execute_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                // L-11: bind worker identity for audit attribution.
                                if let Err(e) = result.sign_with_worker_id(
                                    key_clone.signing_key().as_bytes(),
                                    worker_identity(),
                                ) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign job result");
                                }

                                // FU-2: cache the SIGNED terminal result BEFORE publishing, so a
                                // retry that arrives because the *reply* (not the execution)
                                // failed still finds it. Keyed on job_id; bounded by TTL + size +
                                // count (see `job_idempotency`).
                                if !req.dry_run {
                                    match serde_json::to_vec(&result) {
                                        Ok(bytes) => crate::job_idempotency::JOB_RESULT_CACHE.put(
                                            result.job_id,
                                            result.clone(),
                                            bytes.len(),
                                        ),
                                        Err(e) => ::tracing::warn!(
                                            job_id = %result.job_id, error = %e,
                                            "idempotency: could not serialize result for cache sizing; not caching"
                                        ),
                                    }
                                }

                                match result.status {
                                    JobStatus::Success => {
                                        ::tracing::info!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job completed");
                                    }
                                    JobStatus::Failed => {
                                        ::tracing::warn!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job failed");
                                    }
                                    _ => {}
                                }

                                if let Err(e) = publish_result_with_retry(
                                    &nc_clone,
                                    &result,
                                    3,
                                    reply_to,
                                    &key_clone,
                                )
                                .await
                                {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to publish job result");
                                }

                                drop(permit);
                            });
                        }
                    }
                }
            }
        }
    });

    // ── Pipeline jobs task ────────────────────────────────────────────────
    let pipe_nc = nc.clone();
    let pipe_runtime = runtime.clone();
    let pipe_key = shared_key.clone();
    let pipe_sem = pipeline_semaphore.clone();
    let mut pipe_shutdown = shutdown_rx.clone();

    let pipe_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = pipe_shutdown.changed() => break,
                permit_res = pipe_sem.clone().acquire_owned() => {
                    let permit = match permit_res {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    tokio::select! {
                        _ = pipe_shutdown.changed() => break,
                        msg_opt = pipeline_sub.next() => {
                            let msg = match msg_opt {
                                Some(m) => m,
                                None => break,
                            };

                            let cx = if let Some(ref headers) = msg.headers {
                                crate::trace_nats::extract_trace_context(headers)
                            } else {
                                opentelemetry::Context::new()
                            };

                            // SECURITY: cap payload size before deserialization.
                            const MAX_PIPELINE_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB
                            if msg.payload.len() > MAX_PIPELINE_PAYLOAD_BYTES {
                                ::tracing::error!(
                                    payload_bytes = msg.payload.len(),
                                    "SECURITY: rejecting oversized pipeline job payload"
                                );
                                continue;
                            }
                            let req: PipelineJobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    ::tracing::error!(error = %e, "Failed to decode pipeline job request");
                                    continue;
                                }
                            };

                            ::tracing::info!(job_id = %req.job_id, steps = req.steps.len(), "Received pipeline job");

                            let nc_clone = pipe_nc.clone();
                            let runtime_clone = pipe_runtime.clone();
                            let key_clone = pipe_key.clone();
                            let wire_reply = msg.reply.clone().map(|r: async_nats::Subject| r.to_string());
                            // H-1: see `pick_trusted_reply_topic` —
                            // pipeline path uses the same wire/signed
                            // reconciliation as single-node jobs.
                            let reply_to = pick_trusted_reply_topic(
                                req.job_id,
                                req.reply_topic.as_deref(),
                                wire_reply.as_deref(),
                            );

                            tokio::task::spawn(async move {
                                // FU-2 (R2-5) pipeline idempotency: a controller transport-retry
                                // re-sends the same job_id (fresh nonce) AFTER the original ran.
                                // Re-publish the cached signed payload bytes instead of re-running
                                // the pipeline (which would repeat every step's side effects). The
                                // bytes are still within the 300s JobResult freshness window, so
                                // they're re-published as-is. (PipelineJobRequest has no dry_run.)
                                if let Some(cached) =
                                    crate::job_idempotency::PIPELINE_PAYLOAD_CACHE.get(req.job_id)
                                {
                                    ::tracing::info!(
                                        job_id = %req.job_id,
                                        "idempotency: re-publishing cached pipeline result for \
                                         re-seen job_id (transport retry); skipping re-execution"
                                    );
                                    let publish_result = if let Some(reply) = reply_to {
                                        publish_bytes_with_retry(&nc_clone, reply, cached, 3).await
                                    } else {
                                        let result_topic =
                                            format!("talos.pipeline.results.{}", req.job_id);
                                        publish_bytes_with_retry(&nc_clone, result_topic, cached, 3).await
                                    };
                                    if let Err(e) = publish_result {
                                        ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to publish cached pipeline result");
                                    }
                                    drop(permit);
                                    return;
                                }

                                let mut result =
                                    execute_pipeline_job(&cx, req.clone(), runtime_clone, key_clone.clone()).await;

                                // L-11: bind worker identity for audit attribution.
                                if let Err(e) = result.sign_with_worker_id(
                                    key_clone.signing_key().as_bytes(),
                                    worker_identity(),
                                ) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign pipeline result");
                                }

                                match result.overall_status {
                                    JobStatus::Success => {
                                        ::tracing::info!(
                                            job_id = %result.job_id,
                                            duration_ms = result.total_time_ms,
                                            steps = result.step_results.len(),
                                            "Pipeline completed"
                                        );
                                    }
                                    JobStatus::Failed => {
                                        ::tracing::warn!(
                                            job_id = %result.job_id,
                                            duration_ms = result.total_time_ms,
                                            "Pipeline failed"
                                        );
                                    }
                                    _ => {}
                                }

                                // M-7: size-gate pipeline results too. Same
                                // motivation as single-node: oversized payloads
                                // silently fail at the NATS broker; degrade to a
                                // small Failed result so the controller gets a
                                // signed reply.
                                let serialized = serde_json::to_vec(&result).unwrap_or_default();
                                let cap = max_job_result_bytes();
                                let payload = if serialized.len() > cap {
                                    ::tracing::error!(
                                        job_id = %result.job_id,
                                        serialized_bytes = serialized.len(),
                                        cap_bytes = cap,
                                        "PipelineJobResult exceeds NATS publish cap — substituting Failed status"
                                    );
                                    let mut replacement = PipelineJobResult {
                                        job_id: result.job_id,
                                        overall_status: JobStatus::Failed,
                                        step_results: vec![],
                                        final_output: serde_json::json!({
                                            "error": "pipeline_result_too_large",
                                            "diag": {
                                                "serialized_bytes": serialized.len(),
                                                "cap_bytes": cap,
                                                "note": "Worker dropped the original step_results/final_output to keep \
                                                         under WORKER_MAX_JOB_RESULT_BYTES. Reduce per-step output size or \
                                                         raise the cap if this is legitimate."
                                            }
                                        }),
                                        total_time_ms: result.total_time_ms,
                                        signature: vec![],
                                        result_nonce: String::new(),
                                        worker_id: String::new(),
                                    };
                                    // L-11: bind worker identity for audit attribution.
                                    if let Err(e) = replacement.sign_with_worker_id(
                                        key_clone.signing_key().as_bytes(),
                                        worker_identity(),
                                    ) {
                                        ::tracing::error!(
                                            job_id = %result.job_id,
                                            error = %e,
                                            "Failed to sign oversized pipeline replacement"
                                        );
                                    }
                                    bytes::Bytes::from(
                                        serde_json::to_vec(&replacement).unwrap_or_default(),
                                    )
                                } else {
                                    bytes::Bytes::from(serialized)
                                };

                                // FU-2: cache the final signed payload bytes BEFORE publishing, so
                                // a retry that arrives because the *reply* (not the execution)
                                // failed re-publishes the identical bytes instead of re-running the
                                // pipeline. `Bytes::clone` is a cheap refcount bump.
                                crate::job_idempotency::PIPELINE_PAYLOAD_CACHE.put(
                                    result.job_id,
                                    payload.clone(),
                                    payload.len(),
                                );

                                // Single-publish architecture (mirrors single-job
                                // results, see publish_result_with_retry above for
                                // the full rationale + r301 context). Pipeline
                                // results have only one consumer today (the engine
                                // dispatcher via request-reply), so the
                                // pre-existing fire-and-forget path was already
                                // unused in practice. Adding a second consumer in
                                // the future + verify() at both → would re-enter
                                // the JOB_NONCE_CACHE race we just unlanded.
                                let publish_result = if let Some(reply) = reply_to {
                                    publish_bytes_with_retry(&nc_clone, reply, payload, 3).await
                                } else {
                                    let result_topic = format!("talos.pipeline.results.{}", result.job_id);
                                    publish_bytes_with_retry(&nc_clone, result_topic, payload, 3).await
                                };
                                if let Err(e) = publish_result {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to publish pipeline result");
                                }

                                drop(permit);
                            });
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        // MCP-667 (2026-05-13): listen for BOTH SIGTERM and SIGINT via
        // the shared `talos_shutdown::wait_for_shutdown` helper. Pre-fix
        // the worker only handled SIGINT (Ctrl+C); under K8s pod
        // termination the kubelet sends SIGTERM, which was unobserved —
        // in-flight WASM executions, NATS publishes, and result-
        // collector flushes were aborted at SIGKILL after the grace
        // period elapsed instead of draining cleanly. Sibling fix to
        // the controller-side change at `with_graceful_shutdown` —
        // both binaries now route through the same shutdown surface
        // that carries the MCP-501 install-failure handling.
        _ = talos_shutdown::wait_for_shutdown() => {
            ::tracing::info!("Shutdown signal received, draining in-flight jobs...");
            let _ = shutdown_tx.send(true);
        }
        _ = single_handle => {},
        _ = pipe_handle => {},
    }

    // ========================================================================
    // GRACEFUL SHUTDOWN
    // ========================================================================

    println!("\n=== Shutting Down ===");

    println!("[1/3] Waiting for in-flight jobs to complete...");
    let shutdown_timeout = tokio::time::Duration::from_secs(30);
    let drain_start = std::time::Instant::now();

    while (semaphore.available_permits() < MAX_CONCURRENT_JOBS
        || pipeline_semaphore.available_permits() < MAX_CONCURRENT_PIPELINE_JOBS
        || runtime.active_executions() > 0)
        && drain_start.elapsed() < shutdown_timeout
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    if runtime.active_executions() > 0 {
        ::tracing::warn!(
            remaining = runtime.active_executions(),
            "Forcing shutdown with jobs still running"
        );
    } else {
        ::tracing::info!("All in-flight jobs drained successfully");
    }
    println!("      All jobs completed");

    println!("[2/3] Flushing traces...");
    tracing::shutdown_tracing();
    println!("      Traces flushed");

    println!("[3/3] Closing connections...");
    drop(nc);
    println!("      Connections closed");

    println!("\nWorker shutdown complete");
    Ok(())
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
}

#[cfg(test)]
mod oci_layer_tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    }

    #[test]
    fn verified_when_digest_matches() {
        let payload = b"\0asm\x01\x00\x00\x00";
        let expected = sha256_hex(payload);
        let v = verify_oci_layer(payload, Some(&expected));
        assert!(matches!(v, LayerVerdict::Verified { .. }));
    }

    #[test]
    fn mismatch_when_bytes_differ_from_manifest() {
        let payload = b"original wasm bytes";
        // What the registry CLAIMED — but the bytes we pulled are different.
        let lying_digest = sha256_hex(b"different bytes from what was pulled");
        let v = verify_oci_layer(payload, Some(&lying_digest));
        match v {
            LayerVerdict::DigestMismatch { expected, computed } => {
                assert_eq!(expected, lying_digest);
                assert_eq!(computed, sha256_hex(payload));
                assert_ne!(expected, computed);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn accepted_unverified_when_manifest_omits_layer() {
        // Some malformed registries return a manifest with no layer
        // descriptor. We accept-with-warning rather than fail closed —
        // matches legacy behaviour and avoids breaking pulls from
        // not-quite-spec-compliant registries.
        let v = verify_oci_layer(b"anything", None);
        assert_eq!(v, LayerVerdict::AcceptedUnverified);
    }

    #[test]
    fn empty_layer_still_verifies_against_correct_digest() {
        // Empty bytes have a known sha256:e3b0c4...
        let expected = sha256_hex(&[]);
        assert!(matches!(
            verify_oci_layer(&[], Some(&expected)),
            LayerVerdict::Verified { .. }
        ));
    }

    #[test]
    fn digest_format_includes_sha256_prefix() {
        // sanity-check: the helper produces the same `sha256:HEX` format
        // that `OciDescriptor.digest` declares — string compare must work.
        let payload = b"x";
        let expected = sha256_hex(payload);
        assert!(expected.starts_with("sha256:"));
        assert_eq!(expected.len(), "sha256:".len() + 64);
    }

    // ---- SigstorePolicy + cosign_verify_argv ----

    #[test]
    fn sigstore_policy_default_is_disabled() {
        // Use a serial scope guard so concurrent tests don't race on env.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
        assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Disabled);
    }

    #[test]
    fn sigstore_policy_parses_required_aliases() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["true", "1", "required"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", v);
            assert_eq!(
                SigstorePolicy::from_env(),
                SigstorePolicy::Required,
                "value `{v}` should map to Required"
            );
        }
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn sigstore_policy_parses_audit_aliases() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["audit", "warn"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", v);
            assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Audit);
        }
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn sigstore_policy_unknown_value_falls_back_to_disabled() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("TALOS_SIGSTORE_REQUIRED", "yes-please");
        // Fail-safe default: anything we don't recognise is treated as
        // Disabled, NOT as Required. Operators get a clear "verification
        // didn't run" signal in logs rather than silent failures.
        assert_eq!(SigstorePolicy::from_env(), SigstorePolicy::Disabled);
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    // ---- Wasm-security review 2026-05-22 (MEDIUM-4) ----
    //
    // Production-gate the silent-Disabled fallthrough. The pure parser
    // (`from_env_str`) keeps the lenient default; the production gate
    // (`enforce_production_sigstore_policy_explicit`) refuses to boot
    // when the operator hasn't made an explicit choice. Mirrors the
    // `TALOS_AOT_HMAC_KEY` boot discipline. Tests below pin both the
    // parse contract and the explicit-vs-silent distinction; the
    // production-gate function itself is tested indirectly via the
    // `raw_env_is_explicit` predicate (the gate just composes parser
    // + predicate + production flag).

    #[test]
    fn sigstore_policy_parses_explicit_disabled_aliases() {
        // Operators wanting Disabled in production set one of these
        // so the production-gate sees an explicit choice.
        for v in ["disabled", "off", "0", "false", "no"] {
            assert_eq!(
                SigstorePolicy::from_env_str(v),
                SigstorePolicy::Disabled,
                "value `{v}` should map to Disabled"
            );
        }
    }

    #[test]
    fn sigstore_policy_parser_handles_case_and_whitespace() {
        // Operators copy values out of secret managers / CI logs which
        // sometimes add whitespace or uppercase. The pure parser
        // normalises both. Pre-fix, `Required` was case-sensitive and
        // " REQUIRED" silently mapped to Disabled.
        assert_eq!(
            SigstorePolicy::from_env_str("REQUIRED"),
            SigstorePolicy::Required
        );
        assert_eq!(
            SigstorePolicy::from_env_str("Required"),
            SigstorePolicy::Required
        );
        assert_eq!(
            SigstorePolicy::from_env_str("  audit  "),
            SigstorePolicy::Audit
        );
        assert_eq!(
            SigstorePolicy::from_env_str("\tDISABLED\n"),
            SigstorePolicy::Disabled
        );
    }

    #[test]
    fn sigstore_raw_env_is_explicit_distinguishes_silent_from_chosen() {
        // The production gate fires ONLY when the operator's choice
        // is ambiguous (empty / unrecognised). Every recognised value —
        // including the Disabled aliases — counts as explicit.
        for v in [
            "required",
            "true",
            "1",
            "audit",
            "warn",
            "disabled",
            "off",
            "0",
            "false",
            "no",
            "  REQUIRED  ", // case + whitespace normalisation
        ] {
            assert!(
                SigstorePolicy::raw_env_is_explicit(v),
                "`{v}` must be considered explicit"
            );
        }

        // The silent-default footgun cases the production-gate
        // protects against.
        for v in [
            "",
            "  ",
            "\t\n",
            "yes-please",
            "true-ish",
            "maybe",
            "off-ish",
        ] {
            assert!(
                !SigstorePolicy::raw_env_is_explicit(v),
                "`{v}` must be considered NOT explicit (production-gate target)"
            );
        }
    }

    #[test]
    fn sigstore_production_gate_admits_when_not_in_production() {
        // Sanity: the production gate is a no-op on dev/test hosts.
        // Tests run with `is_production() == false` by default; if
        // this ever stops being true, the assertion below will fail
        // loudly and we'll know to revisit.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
        // No env var set; in dev this MUST be Ok(Disabled).
        let result = enforce_production_sigstore_policy_explicit();
        assert!(
            result.is_ok(),
            "production gate must admit silent-default on dev hosts — got {result:?}"
        );
        assert_eq!(result.unwrap(), SigstorePolicy::Disabled);
    }

    #[test]
    fn sigstore_production_gate_admits_every_explicit_value_on_dev() {
        // Operator-recognised values pass the gate in any environment.
        let _g = ENV_LOCK.lock().unwrap();
        for v in ["required", "audit", "disabled"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", v);
            let result = enforce_production_sigstore_policy_explicit();
            assert!(
                result.is_ok(),
                "explicit `{v}` must pass the gate — got {result:?}"
            );
        }
        std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
    }

    #[test]
    fn sigstore_production_gate_refuses_silent_default_in_production() {
        // The point of the gate. With `RUST_ENV=production` AND
        // `TALOS_SIGSTORE_REQUIRED` unset / empty / garbage, the boot
        // path must return Err — refusing to start rather than
        // silently devolving to no-verification.
        let _g = ENV_LOCK.lock().unwrap();
        let prior_rust_env = std::env::var("RUST_ENV").ok();
        let prior_sigstore = std::env::var("TALOS_SIGSTORE_REQUIRED").ok();

        std::env::set_var("RUST_ENV", "production");

        for ambiguous in ["", "  ", "yes-please", "true-ish"] {
            if ambiguous.is_empty() {
                std::env::remove_var("TALOS_SIGSTORE_REQUIRED");
            } else {
                std::env::set_var("TALOS_SIGSTORE_REQUIRED", ambiguous);
            }
            let result = enforce_production_sigstore_policy_explicit();
            assert!(
                result.is_err(),
                "production gate must refuse silent / unrecognised value `{ambiguous:?}` — got {result:?}"
            );
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("TALOS_SIGSTORE_REQUIRED"),
                "error message must name the env var so operators find the fix — got `{err_msg}`"
            );
            // Actionable error: must mention all three remediation paths.
            assert!(
                err_msg.contains("required"),
                "error must mention `required` option"
            );
            assert!(
                err_msg.contains("audit"),
                "error must mention `audit` option"
            );
            assert!(
                err_msg.contains("disabled"),
                "error must mention `disabled` option"
            );
        }

        // And the converse: setting an explicit value in production
        // passes the gate.
        for explicit in ["required", "audit", "disabled"] {
            std::env::set_var("TALOS_SIGSTORE_REQUIRED", explicit);
            let result = enforce_production_sigstore_policy_explicit();
            assert!(
                result.is_ok(),
                "production gate must admit explicit `{explicit}` — got {result:?}"
            );
        }

        // Restore prior env state so we don't poison other tests
        // sharing ENV_LOCK.
        match prior_rust_env {
            Some(v) => std::env::set_var("RUST_ENV", v),
            None => std::env::remove_var("RUST_ENV"),
        }
        match prior_sigstore {
            Some(v) => std::env::set_var("TALOS_SIGSTORE_REQUIRED", v),
            None => std::env::remove_var("TALOS_SIGSTORE_REQUIRED"),
        }
    }

    #[test]
    fn cosign_argv_includes_identity_and_issuer_pinning() {
        // SECURITY: this test guards against well-meaning "simplifications"
        // of cosign_verify_argv that drop the identity or issuer check —
        // either omission would let a valid Sigstore signature from ANY
        // workflow on ANY repo pass verification.
        let argv = cosign_verify_argv(
            "ghcr.io/owner/talos-tools/foo:v1",
            "^https://github\\.com/owner/talos/.+",
            "https://token.actions.githubusercontent.com",
        );
        assert_eq!(argv[0], "verify");
        assert!(
            argv.iter().any(|a| a == "--certificate-identity-regexp"),
            "must pin certificate identity"
        );
        assert!(
            argv.iter().any(|a| a == "--certificate-oidc-issuer"),
            "must pin OIDC issuer"
        );
        // Reference is always last so cosign treats it as the positional arg.
        assert_eq!(argv.last().unwrap(), "ghcr.io/owner/talos-tools/foo:v1");
    }

    #[test]
    fn cosign_argv_propagates_identity_verbatim() {
        // No string mangling: the regex passed by config must reach cosign
        // unchanged, otherwise operator-curated identity patterns silently
        // become broader than intended.
        let identity = "^https://github\\.com/MY_ORG/talos/\\.github/workflows/template-publish\\.yml@refs/heads/main$";
        let argv = cosign_verify_argv("ref", identity, "issuer");
        let pos = argv
            .iter()
            .position(|a| a == "--certificate-identity-regexp")
            .unwrap();
        assert_eq!(argv[pos + 1], identity);
    }

    // Serial guard for env-mutating tests in this module. Without it,
    // cargo's parallel test runner can race on the global env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ─── M-1: Sigstore identity regexp validator ───────────────────────────
    //
    // The validator is the only thing standing between a footgun like
    // `TALOS_SIGSTORE_IDENTITY_REGEXP=".*"` and a Required-mode
    // production deploy that silently accepts any Fulcio cert. These
    // tests cover the rejection classes and the happy path so a
    // future refactor can't relax the policy without explicit intent.

    #[test]
    fn sigstore_regexp_empty_is_rejected() {
        assert_eq!(
            validate_sigstore_identity_regexp(""),
            Err(SigstoreRegexpRejection::Empty)
        );
    }

    #[test]
    fn sigstore_regexp_catchall_patterns_are_rejected() {
        for pattern in [".*", ".+", ".", "^.*$", "^.+$", "^.$", "^.*", ".*$"] {
            assert_eq!(
                validate_sigstore_identity_regexp(pattern),
                Err(SigstoreRegexpRejection::TooBroad),
                "pattern {pattern:?} should be rejected as too broad"
            );
        }
    }

    #[test]
    fn sigstore_regexp_catchall_with_whitespace_is_rejected() {
        // Operators sometimes paste env vars with leading/trailing
        // spaces. Without trim, " .* " would slip through.
        assert_eq!(
            validate_sigstore_identity_regexp(" .* "),
            Err(SigstoreRegexpRejection::TooBroad)
        );
    }

    #[test]
    fn sigstore_regexp_invalid_regex_is_rejected() {
        // Unclosed bracket: cosign would fail at runtime with an opaque
        // upstream error. Fail closed at startup instead.
        assert_eq!(
            validate_sigstore_identity_regexp("^https://github\\.com/owner/talos/["),
            Err(SigstoreRegexpRejection::InvalidRegex)
        );
    }

    #[test]
    fn sigstore_regexp_workflow_pattern_without_at_anchor_is_rejected() {
        // The CLAUDE.md guidance is explicit: a workflow-URL pattern
        // missing the trailing `@` is spoofable via a fork repo named
        // `workflow.yml-evil.yml`. This test guards that policy.
        let pattern =
            "^https://github\\.com/owner/talos/\\.github/workflows/template-publish\\.yml";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingWorkflowAnchor)
        );
    }

    #[test]
    fn sigstore_regexp_workflow_pattern_with_at_anchor_is_accepted() {
        let pattern =
            "^https://github\\.com/owner/talos/\\.github/workflows/template-publish\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "well-formed workflow pattern with @ anchor should pass: got {:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn sigstore_regexp_workflow_pattern_anchored_to_ref_is_accepted() {
        // Patterns sometimes also pin the ref name after the `@`:
        // `…/foo.yml@refs/heads/main$`. The `$` anchor is fine — we
        // just need the `@` somewhere before any final `$`.
        let pattern = "^https://github\\.com/owner/talos/\\.github/workflows/template-publish\\.yml@refs/heads/main$";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "workflow pattern with @refs/...$ tail should pass"
        );
    }

    #[test]
    fn sigstore_regexp_non_github_pattern_is_accepted() {
        // We only enforce the @-anchor convention on github.com
        // workflow URLs. Operators using GitLab CI, custom OIDC
        // providers, or other identity formats are out of scope for
        // that specific check — they get the regex-validity and
        // catchall checks only.
        assert!(validate_sigstore_identity_regexp("^https://gitlab\\.com/owner/talos/").is_ok());
    }

    // ─── L-14: github.com permissive-pattern anchoring ─────────────────────

    #[test]
    fn sigstore_regexp_github_without_workflow_path_is_rejected() {
        // The simplest permissive pattern: matches every OIDC identity
        // from github.com regardless of repo or workflow.
        let pattern = "^https://github\\.com/.*";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingGithubWorkflowPath),
            "github.com pattern without workflows path must be rejected"
        );
    }

    #[test]
    fn sigstore_regexp_github_owner_wildcarded_is_rejected() {
        // The classical "any owner, any repo, my workflow file" attack
        // surface — a forked repo with the same workflow filename
        // could sign as us.
        for pattern in [
            "^https://github\\.com/.*/\\.github/workflows/publish\\.yml@",
            "^https://github\\.com/.+/talos/\\.github/workflows/publish\\.yml@",
            "^https://github\\.com/[^/]+/talos/\\.github/workflows/publish\\.yml@",
        ] {
            assert_eq!(
                validate_sigstore_identity_regexp(pattern),
                Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo),
                "unpinned owner/repo pattern must be rejected: {pattern}"
            );
        }
    }

    #[test]
    fn sigstore_regexp_github_repo_wildcarded_is_rejected() {
        // Wildcard in the REPO position is still unpinned — `talos.*`
        // (any-character then any-suffix) matches any repo name
        // starting with `talos`.
        let pattern = "^https://github\\.com/myorg/talos.*/\\.github/workflows/publish\\.yml@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo)
        );
    }

    #[test]
    fn sigstore_regexp_github_dot_in_owner_or_repo_is_literal_when_escaped() {
        // Some orgs/repos legitimately contain `.` — `my.org` or
        // `my-tool.io`. Escaped `\.` is a literal dot and should NOT
        // trip the unpinned-wildcard check.
        let pattern = "^https://github\\.com/my\\.org/my\\.repo/\\.github/workflows/publish\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "escaped literal dot in owner/repo should pass: {:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn sigstore_regexp_github_pinned_owner_repo_is_accepted() {
        // The canonical correct form, per CLAUDE.md guidance.
        let pattern =
            "^https://github\\.com/ehelbig1/talos/\\.github/workflows/template-publish\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "pinned owner/repo with @-anchor must pass: {:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn sigstore_regexp_unescaped_github_host_is_handled() {
        // Some operators write `github.com` without the regex-escape
        // for `.` (technically broader — `.` matches any char — but
        // we don't reject it here because it's a separate issue).
        // The path-presence check should still fire on the raw form.
        let pattern = "^https://github.com/.*";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingGithubWorkflowPath)
        );
    }

    // Wasm-security review 2026-05-23: `^` start-anchor enforcement on
    // any pattern that begins with `https://`. Without `^`, the
    // `https://...` substring could match anywhere inside the SAN URI;
    // all the documented operator examples in human_reason() already
    // use the anchor, so this is purely closing a documentation/code
    // drift hole.
    #[test]
    fn sigstore_regexp_unanchored_https_pattern_is_rejected() {
        let pattern = "https://github\\.com/owner/talos/\\.github/workflows/publish\\.yml@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingStartAnchor),
            "unanchored https:// pattern must be rejected"
        );
    }

    #[test]
    fn sigstore_regexp_anchored_https_pattern_is_accepted() {
        // Confirm the canonical form still passes after the new check.
        let pattern = "^https://github\\.com/owner/talos/\\.github/workflows/publish\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "anchored https:// pattern must pass: {:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn sigstore_regexp_non_https_pattern_does_not_require_anchor() {
        // SAN-email patterns / custom-OIDC patterns shouldn't be forced
        // to start with `^`. Only `https://`-prefixed patterns are
        // affected by the new rule.
        let pattern = "ci@example\\.com$";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "non-https pattern without ^ should pass: {:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    // ─── H-3: OCI manifest size gate ──────────────────────────────────────

    #[test]
    fn manifest_size_under_cap_is_accepted() {
        // The realistic case — a normal-sized WASM artifact.
        assert_eq!(
            check_manifest_layer_sizes(&[5 * 1024 * 1024], 64 * 1024 * 1024),
            ManifestSizeVerdict::Ok
        );
    }

    #[test]
    fn manifest_size_exactly_at_cap_is_accepted() {
        // Boundary: equal to cap is OK (off-by-one guard).
        assert_eq!(
            check_manifest_layer_sizes(&[64 * 1024 * 1024], 64 * 1024 * 1024),
            ManifestSizeVerdict::Ok
        );
    }

    #[test]
    fn manifest_size_one_byte_over_cap_is_rejected() {
        let verdict = check_manifest_layer_sizes(&[64 * 1024 * 1024 + 1], 64 * 1024 * 1024);
        assert!(
            matches!(verdict, ManifestSizeVerdict::Oversized { .. }),
            "should reject when 1 byte over cap; got {verdict:?}"
        );
    }

    #[test]
    fn manifest_negative_size_is_rejected() {
        // A forged manifest could try to bypass the gate by claiming
        // a negative size (`size: i64` allows it per spec). Treat any
        // negative value as oversized — fail closed.
        assert!(matches!(
            check_manifest_layer_sizes(&[-1], 64 * 1024 * 1024),
            ManifestSizeVerdict::Oversized { declared: -1, .. }
        ));
    }

    #[test]
    fn manifest_with_one_oversized_layer_among_many_is_rejected() {
        // Multi-layer artifacts: if ANY layer is oversized, refuse.
        let layers = [1024, 2048, 1_000_000_000_000];
        assert!(matches!(
            check_manifest_layer_sizes(&layers, 64 * 1024 * 1024),
            ManifestSizeVerdict::Oversized { .. }
        ));
    }

    #[test]
    fn manifest_empty_layers_is_accepted() {
        // A manifest with no layers is OK at the size-gate level —
        // downstream code will report "WASM payload not found".
        assert_eq!(
            check_manifest_layer_sizes(&[], 64 * 1024 * 1024),
            ManifestSizeVerdict::Ok
        );
    }

    #[test]
    fn max_oci_layer_bytes_uses_default_when_env_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WORKER_MAX_OCI_LAYER_BYTES");
        assert_eq!(max_oci_layer_bytes(), DEFAULT_MAX_OCI_LAYER_BYTES);
    }

    #[test]
    fn max_oci_layer_bytes_uses_default_when_env_is_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_OCI_LAYER_BYTES", "0");
        // 0 means "use default" — same convention as the rest of the
        // worker's nonzero-or-default env helpers (see
        // `nonzero_env_or_default` in runtime.rs).
        assert_eq!(max_oci_layer_bytes(), DEFAULT_MAX_OCI_LAYER_BYTES);
        std::env::remove_var("WORKER_MAX_OCI_LAYER_BYTES");
    }

    #[test]
    fn max_oci_layer_bytes_uses_default_when_env_malformed() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_OCI_LAYER_BYTES", "not-a-number");
        assert_eq!(max_oci_layer_bytes(), DEFAULT_MAX_OCI_LAYER_BYTES);
        std::env::remove_var("WORKER_MAX_OCI_LAYER_BYTES");
    }

    #[test]
    fn max_oci_layer_bytes_respects_valid_env_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_OCI_LAYER_BYTES", "33554432"); // 32 MiB
        assert_eq!(max_oci_layer_bytes(), 33_554_432);
        std::env::remove_var("WORKER_MAX_OCI_LAYER_BYTES");
    }

    // ─── M-7: JobResult publish-size cap ──────────────────────────────────

    #[test]
    fn truncate_oversized_replaces_payload_and_marks_failed() {
        let original = JobResult {
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000)}),
            logs: vec!["a".to_string(); 1000],
            execution_time_ms: 42,
            signature: vec![0; 32],
            result_nonce: "1700000000:abc".to_string(),
            worker_id: String::new(),
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        // Identity bound: same job_id so the controller can correlate.
        assert_eq!(replacement.job_id, original.job_id);
        // Status downgraded to Failed — the original Success is no
        // longer accurate because the result didn't reach the
        // controller.
        assert_eq!(replacement.status, JobStatus::Failed);
        // Payload replaced with a small diagnostic blob.
        assert!(replacement.output_payload.get("error").is_some());
        assert!(replacement.output_payload.get("diag").is_some());
        // Logs and execution time preserved for correlation.
        assert!(!replacement.logs.is_empty());
        assert_eq!(replacement.execution_time_ms, 42);
        // Signature MUST be cleared so the caller can't accidentally
        // publish an unsigned replacement (the caller is expected to
        // re-sign before publishing).
        assert!(replacement.signature.is_empty());
        assert!(replacement.result_nonce.is_empty());
    }

    #[test]
    fn truncate_oversized_replacement_serializes_under_cap() {
        // The replacement itself must fit comfortably under any
        // reasonable cap, otherwise we'd loop forever.
        let original = JobResult {
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000_000)}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        let bytes = serde_json::to_vec(&replacement).unwrap();
        // Replacement is small — well under any realistic cap.
        assert!(
            bytes.len() < 4096,
            "replacement should serialize to a small payload; got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn max_job_result_bytes_uses_default_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
        assert_eq!(max_job_result_bytes(), DEFAULT_MAX_JOB_RESULT_BYTES);
    }

    #[test]
    fn max_job_result_bytes_respects_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_JOB_RESULT_BYTES", "8388608"); // 8 MiB
        assert_eq!(max_job_result_bytes(), 8_388_608);
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
    }

    // ─── H-1: pick_trusted_reply_topic decision matrix ────────────────────
    //
    // The whole point of H-1 is that a NATS-channel attacker who
    // substitutes `msg.reply` cannot redirect the worker's signed
    // JobResult to an attacker-controlled subject. These tests pin
    // the policy at the function boundary so a future "simplification"
    // can't silently re-introduce the regression.

    #[test]
    fn pick_reply_signed_and_wire_match() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.abc"), Some("_INBOX.abc"));
        assert_eq!(r.as_deref(), Some("_INBOX.abc"));
    }

    #[test]
    fn pick_reply_signed_and_wire_mismatch_returns_signed() {
        // SECURITY: an attacker substituted `msg.reply` — the worker
        // MUST publish to the signed value, not the wire value.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some("talos.admin.commands"));
        assert_eq!(
            r.as_deref(),
            Some("_INBOX.legit"),
            "wire taking priority would be the security regression"
        );
    }

    #[test]
    fn pick_reply_signed_only() {
        // msg.reply stripped in transit; signed value is authoritative.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.signed"), None);
        assert_eq!(r.as_deref(), Some("_INBOX.signed"));
    }

    #[test]
    fn pick_reply_wire_only_backward_compat() {
        // Legacy controller / non-NATS transport that doesn't
        // pre-allocate inboxes. The worker accepts msg.reply
        // verbatim — this is the path the H-1 binding closes for
        // upgraded controllers but keeps available for old ones.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, Some("_INBOX.legacy"));
        assert_eq!(r.as_deref(), Some("_INBOX.legacy"));
    }

    #[test]
    fn pick_reply_neither_present() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, None);
        assert_eq!(r, None);
    }

    #[test]
    fn pick_reply_mismatch_does_not_publish_to_attacker_subject() {
        // Specific regression guard: an attacker substituting a
        // sensitive admin subject MUST NOT result in the worker
        // publishing there. This is the whole point of H-1.
        let jid = uuid::Uuid::new_v4();
        let bad_subjects = [
            "talos.admin.commands",
            "talos.jobs",          // would create a NATS loop
            "talos.pipeline.jobs", // same
            "$SYS.REQ.ACCOUNT",    // NATS system subject
            "_INBOX.attacker.xyz", // inbox-prefix but not the signed one
        ];
        for bad in bad_subjects {
            let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some(bad));
            assert_eq!(
                r.as_deref(),
                Some("_INBOX.legit"),
                "H-1 regression: wire subject {bad:?} leaked through"
            );
        }
    }
}
// build test 1773350887
