//! Module acquisition for job execution: inline `wasm_bytes`, OCI
//! registry pull (with Sigstore signature verification, manifest size
//! gates and layer-digest verification), digest-keyed Redis cache, and
//! filesystem fallback — plus the Sigstore policy / cosign plumbing.
//!
//! Extracted verbatim from `main.rs::execute_job` (May-2026). All
//! security ordering, log messages and error strings are preserved
//! byte-for-byte; see [`fetch`].

use crate::error_sanitize::sanitize_error_message;
use crate::job_span::JobSpan;
use crate::runtime::TalosRuntime;
use std::sync::OnceLock;
use talos_workflow_job_protocol::JobRequest;

/// A module acquired by [`fetch`], with its attestation provenance.
pub struct FetchedModule {
    /// The WASM component bytes to execute.
    pub bytes: Vec<u8>,
    /// Whether the bytes were cryptographically attested during THIS
    /// worker run: inline `wasm_bytes` from the JobRequest (HMAC over
    /// the job covers sha256(bytes)), a fresh OCI pull that completed
    /// Sigstore + layer-digest checks, or a Redis OCI-cache hit that
    /// re-verified against the manifest digest. When `false`
    /// (`redis:wasm:` direct fetch, filesystem load), the controller's
    /// `expected_wasm_hash` is the only integrity anchor — the caller's
    /// hash-check block MUST refuse to execute without one.
    pub attested_in_this_run: bool,
}

/// Module-acquisition failure. `message` is the exact operator-facing
/// string the pre-extraction inline code placed in the failed
/// `JobResult`'s `output_payload.error` and the job span's `end_error`.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct FetchError {
    pub message: String,
}

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
pub enum ManifestSizeVerdict {
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
pub fn check_manifest_layer_sizes(layer_sizes: &[i64], cap: u64) -> ManifestSizeVerdict {
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
pub enum SigstorePolicy {
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
    pub fn from_env() -> Self {
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
pub fn enforce_production_sigstore_policy_explicit() -> anyhow::Result<SigstorePolicy> {
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

/// Sigstore identity-regexp policy — the validator + rejection enum now
/// live in the shared `talos-sigstore-policy` crate so the worker and the
/// controller's OCI catalog-sync enforce IDENTICAL identity pinning (security
/// review 2026-07-19, P4). Re-exported here to keep existing worker call
/// sites and tests (`validate_sigstore_identity_regexp`, `SigstoreRegexpRejection`,
/// `.human_reason()`) unchanged.
pub use talos_sigstore_policy::{validate_sigstore_identity_regexp, SigstoreRegexpRejection};

/// Build the `cosign verify` argv for a given OCI reference. Pure
/// (no env reads, no I/O) so the security-critical command construction
/// is unit-tested without invoking cosign.
///
/// Cert identity + OIDC issuer come from configuration:
/// - `identity_regexp`: regex matched against the SAN URI of the Fulcio
///   cert. Pin to the workflow URL pattern, e.g.
///   `^https://github\.com/OWNER/talos/\.github/workflows/template-publish\.yml@`
/// - `oidc_issuer`: GitHub Actions = `https://token.actions.githubusercontent.com`
pub fn cosign_verify_argv(
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
pub async fn verify_oci_signature(
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
pub fn parse_cosign_version(stdout: &str) -> Option<(u32, u32, u32)> {
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
pub fn parse_semver_triple(s: &str) -> Option<(u32, u32, u32)> {
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
pub fn cosign_pinned_path() -> Option<&'static std::path::Path> {
    COSIGN_BINARY_PATH.get().map(|p| p.as_path())
}

/// Resolve the `cosign` binary on PATH, pin its absolute path for the
/// process lifetime, and compute its SHA-256.
///
/// The path pin is set as a side-effect of a successful resolve so the
/// M5 hash pin gate at startup and the per-invocation execution path
/// agree on which binary is being checked.
pub async fn resolve_and_hash_cosign_binary() -> anyhow::Result<String> {
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
pub enum LayerVerdict<'a> {
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
pub fn verify_oci_layer<'a>(
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
pub fn is_metadata_service_host(host: &str) -> bool {
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

/// Acquire the WASM module bytes for a job.
///
/// Sources, in order of preference (behaviour unchanged from the
/// pre-extraction `execute_job` inline block):
/// * inline `req.wasm_bytes` (HMAC over the job covers sha256(bytes));
/// * `oci://` pull — metadata-service host gate, HTTP-downgrade gate,
///   Sigstore verification, pre-pull manifest size gate, digest-keyed
///   Redis cache (re-verified on hit), post-pull size + layer-digest
///   verification, cache write only after full attestation;
/// * `redis:wasm:` direct fetch (size-capped);
/// * filesystem fallback (size-capped).
///
/// On failure, [`FetchError::message`] carries — byte-for-byte — the
/// string the caller must place in the failed `JobResult`'s
/// `output_payload.error` AND pass to `span.end_error` (exactly what
/// the pre-extraction inline code emitted). All other span
/// attributes/events and log lines are emitted here.
pub async fn fetch(
    req: &JobRequest,
    runtime: &TalosRuntime,
    span: &mut JobSpan,
) -> Result<FetchedModule, FetchError> {
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
    span.add_event("loading_module");
    let wasm_bytes = if let Some(bytes) = &req.wasm_bytes {
        // PERFORMANCE: Use bytes provided in job request (avoids file I/O)
        // HMAC over the JobRequest covers sha256(bytes) — attested.
        span.set_attribute_int("module_size_bytes", bytes.len() as i64);
        span.set_attribute("module_source", "job_request");
        bytes_attested_in_this_run = true;
        bytes.clone()
    } else if req.module_uri.starts_with("oci://") {
        // Fetch from OCI Registry (e.g. GitHub Container Registry, AWS ECR, JFrog)
        span.add_event("fetching_from_oci_registry");
        span.set_attribute("oci_url", &req.module_uri);

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
                return Err(FetchError { message: err });
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
                return Err(FetchError { message: err_msg });
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
                        return Err(FetchError { message: err });
                    }
                } else {
                    match verify_oci_signature(&image_ref, &identity_regexp, &oidc_issuer).await {
                        Ok(()) => {
                            span.add_event("sigstore_verify_ok");
                        }
                        Err(reason) => match sigstore_policy {
                            SigstorePolicy::Required => {
                                let err = format!("sigstore_required: {reason}");
                                ::tracing::error!(
                                    module_uri = %req.module_uri,
                                    "Sigstore verification failed and policy is required — refusing to execute"
                                );
                                return Err(FetchError { message: err });
                            }
                            SigstorePolicy::Audit => {
                                ::tracing::warn!(
                                    module_uri = %req.module_uri,
                                    reason = %reason,
                                    "Sigstore verification failed but policy is audit — \
                                     continuing execution but NOT caching bytes"
                                );
                                span.add_event("sigstore_verify_failed_audit");
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
                        return Err(FetchError { message: err });
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
                                        span.add_event("oci_cache_hit");
                                        span.set_attribute("module_source", "redis_oci_cache");
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
                                return Err(FetchError { message: err });
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
                                    span.set_attribute("oci_layer_digest", digest);
                                    span.add_event("oci_pull_success");

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
                                    return Err(FetchError { message: err });
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
                                        span.add_event("oci_pull_success_unverified");
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
                                        return Err(FetchError {
                                            message: err.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        ::tracing::warn!(module_uri = %req.module_uri, error = %e, "Failed to pull WASM artifact from OCI registry");
                        let err_msg = format!("oci_pull_error: {}", e);
                        let sanitized_error = sanitize_error_message(&err_msg);
                        span.add_event(&sanitized_error);
                    }
                }
            } // end `if found_bytes.is_none()` cache-miss block
        }

        match found_bytes {
            Some(b) => b,
            None => {
                return Err(FetchError {
                    message: "WASM payload not found in OCI registry".to_string(),
                });
            }
        }
    } else if req.module_uri.starts_with("redis:wasm:") {
        // Fetch from Redis via TalosRuntime's redis client
        span.add_event("fetching_from_redis");

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
                return Err(FetchError { message: err });
            }
            span.set_attribute_int("module_size_bytes", b.len() as i64);
            span.set_attribute("module_source", "redis");
            b
        } else {
            let error_msg =
                "failed to fetch wasm module from redis (not found or redis unavailable)";
            span.set_attribute("error", error_msg);
            return Err(FetchError {
                message: error_msg.to_string(),
            });
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
                    return Err(FetchError { message: err });
                }
                span.set_attribute_int("module_size_bytes", b.len() as i64);
                span.set_attribute("module_source", "filesystem");
                b
            }
            Err(e) => {
                let error_msg = format!("failed to read wasm module: {}", e);
                let sanitized_error = sanitize_error_message(&error_msg);
                span.set_attribute("error", &sanitized_error);
                return Err(FetchError {
                    message: sanitized_error,
                });
            }
        }
    };

    Ok(FetchedModule {
        bytes: wasm_bytes,
        attested_in_this_run: bytes_attested_in_this_run,
    })
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
}
