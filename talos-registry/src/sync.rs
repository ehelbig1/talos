//! OCI registry sync — pulls template manifests from a configured OCI registry
//! and upserts them into the `modules` table with `kind = 'catalog'` and
//! `oci_url` populated. The worker pulls the actual WASM bytes at execution
//! time via the `oci_url` reference; this sync only handles metadata.
//!
//! ## Discovery
//!
//! Two paths, tried in order:
//!
//! 1. **Index artifact** (`{namespace}/_index:latest`) — registry-portable.
//!    The artifact's CONFIG BLOB is a JSON document listing every template
//!    name + tag the operator has published. This is the only mechanism that
//!    works on GHCR / GAR / ECR (none expose `/v2/_catalog`).
//!
//! 2. **`/v2/_catalog`** — legacy, only works on self-hosted Docker registry
//!    (`registry:2`) and similar. Filtered to repos under the configured
//!    namespace prefix. Used when the index artifact returns 404.
//!
//! ## Auth
//!
//! Delegated to `oci_distribution::Client`, which handles anonymous pulls of
//! public packages and the Bearer-token challenge-response that GHCR uses
//! even for anonymous reads. For private packages set
//! `OCI_REGISTRY_USERNAME` + `OCI_REGISTRY_PASSWORD` (PAT works as the
//! password for GHCR private packages).

use anyhow::{Context, Result};
use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client as OciClient, Reference};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// ───────────────────────────────────────────────────────────────────────
// H2 (2026-05-22): Sigstore verification for the `_index` catalog
// artifact AND each per-template artifact. Pre-fix only the worker
// verified signatures on layer pulls at execution time; the controller-
// side catalog sync trusted whatever the registry returned. A tampered
// or MITM'd `_index` could inject arbitrary template entries pointing
// at attacker-controlled image tags. The individual templates would
// still be sigstore-verified at worker execution time, but the catalog
// itself (and the discovery surface it controls) was unauthenticated.
//
// We mirror the worker's policy enum (`Disabled` / `Audit` / `Required`)
// so the operator-facing env vars are identical:
//   * TALOS_SIGSTORE_REQUIRED  (true | audit | <unset>)
//   * TALOS_SIGSTORE_IDENTITY_REGEXP
//   * TALOS_SIGSTORE_OIDC_ISSUER (default: GitHub Actions OIDC)
// ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum SigstorePolicy {
    Disabled,
    Audit,
    Required,
}

impl SigstorePolicy {
    fn from_env() -> Self {
        match env::var("TALOS_SIGSTORE_REQUIRED")
            .unwrap_or_default()
            .as_str()
        {
            "true" | "1" | "required" => Self::Required,
            "audit" | "warn" => Self::Audit,
            _ => Self::Disabled,
        }
    }
}

/// Process-wide pinned absolute path to the `cosign` binary on the
/// controller side. Mirrors the worker's pin (worker/src/main.rs) so
/// every verification invocation targets the SAME binary that the
/// controller's startup resolution touched. Without this, each
/// `Command::new("cosign")` re-walks `PATH` — fine in an immutable
/// container, exploitable anywhere `PATH` is mutable.
static COSIGN_BINARY_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Resolve `cosign` on PATH once and cache the absolute path. Called
/// lazily from `cosign_verify_artifact`; subsequent calls hit the
/// cache. A resolution failure does NOT cache a sentinel — the next
/// verification call will retry, so a slow / racy startup environment
/// converges instead of permanently failing closed.
async fn resolve_cosign_path_cached() -> Option<&'static std::path::Path> {
    if let Some(p) = COSIGN_BINARY_PATH.get() {
        return Some(p.as_path());
    }
    let output = tokio::process::Command::new("which")
        .arg("cosign")
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    let path_buf = std::path::PathBuf::from(path);
    let _ = COSIGN_BINARY_PATH.set(path_buf);
    COSIGN_BINARY_PATH.get().map(|p| p.as_path())
}

/// Verify an OCI artifact's Sigstore signature via the `cosign` binary.
/// Pure-argv wrapper around `cosign verify --certificate-identity-regexp
/// <REGEXP> --certificate-oidc-issuer <ISSUER>` — the same shape used by
/// the worker. Returns `Ok(())` on a clean verification; the caller
/// chooses how to react to `Err(...)` based on policy.
async fn cosign_verify_artifact(
    reference: &str,
    identity_regexp: &str,
    oidc_issuer: &str,
) -> std::result::Result<(), String> {
    // Prefer the cached absolute path so PATH mutations between
    // startup and verification time can't swap the binary.
    let mut command = match resolve_cosign_path_cached().await {
        Some(path) => tokio::process::Command::new(path),
        None => tokio::process::Command::new("cosign"),
    };
    let output = command
        .args([
            "verify",
            "--certificate-identity-regexp",
            identity_regexp,
            "--certificate-oidc-issuer",
            oidc_issuer,
            "--output",
            "json",
            reference,
        ])
        .output()
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "cosign binary not found or unexecutable — install cosign in the controller image"
            );
            "cosign_unavailable".to_string()
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    tracing::warn!(
        reference = %reference,
        exit_code = output.status.code().unwrap_or(-1),
        stderr = %stderr,
        "cosign verify failed (controller-side index/template sync)"
    );
    Err("signature_verification_failed".to_string())
}

/// Verify an OCI artifact against the configured Sigstore policy.
/// Returns:
///   * `Ok(true)`  — verification passed (or policy is Disabled).
///   * `Ok(false)` — Audit-mode failure: the caller MAY proceed but
///                   should log + meter; the artifact is unattested.
///   * `Err(...)`  — Required-mode failure OR misconfiguration that
///                   the caller must surface as a sync error.
///
/// Mirrors the worker's verdict structure so the contract is uniform
/// across both processes. The identity regexp is checked for the
/// known catch-all foot-guns (`.*`, `.+`, etc.) so an operator who
/// sets `TALOS_SIGSTORE_REQUIRED=true` with a permissive pattern
/// discovers it HERE rather than per-pull.
async fn verify_oci_artifact_signature(reference: &Reference) -> Result<bool> {
    let policy = SigstorePolicy::from_env();
    if policy == SigstorePolicy::Disabled {
        return Ok(true);
    }
    let identity_regexp = env::var("TALOS_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
    if identity_regexp.is_empty() {
        let msg = "TALOS_SIGSTORE_IDENTITY_REGEXP is empty — \
                   refusing to verify with no identity pin";
        match policy {
            SigstorePolicy::Required => anyhow::bail!("{msg} (Required policy)"),
            SigstorePolicy::Audit => {
                tracing::warn!("{msg} (Audit mode: continuing without verification)");
                return Ok(false);
            }
            SigstorePolicy::Disabled => unreachable!(),
        }
    }
    // Reject obvious catch-alls so the operator can't silently neuter
    // the gate via env. Pure substring match against known patterns —
    // a defense-in-depth check on top of the worker-side startup
    // validation. Sibling of `validate_sigstore_identity_regexp` in
    // worker/src/main.rs; the canonical home is the worker's helper
    // (the controller never invokes `cosign verify` from anywhere
    // else, so duplicating the short matcher here is cheaper than
    // adding a shared `talos-sigstore-policy` crate for one function).
    let trimmed = identity_regexp.trim();
    if matches!(
        trimmed,
        ".*" | ".+" | "." | "^.*$" | "^.+$" | "^.$" | "^.*" | ".*$"
    ) {
        let msg = format!(
            "TALOS_SIGSTORE_IDENTITY_REGEXP is too broad (`{trimmed}`) — \
             pin it to your workflow URL pattern"
        );
        match policy {
            SigstorePolicy::Required => anyhow::bail!("{msg} (Required policy)"),
            SigstorePolicy::Audit => {
                tracing::warn!("{msg} (Audit mode: continuing without verification)");
                return Ok(false);
            }
            SigstorePolicy::Disabled => unreachable!(),
        }
    }
    let oidc_issuer = env::var("TALOS_SIGSTORE_OIDC_ISSUER")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://token.actions.githubusercontent.com".to_string());
    let reference_str = reference.to_string();
    match cosign_verify_artifact(&reference_str, &identity_regexp, &oidc_issuer).await {
        Ok(()) => {
            tracing::debug!(
                reference = %reference_str,
                "Sigstore verification passed for OCI artifact"
            );
            Ok(true)
        }
        Err(reason) => match policy {
            SigstorePolicy::Required => {
                anyhow::bail!("Sigstore verification failed for {reference_str}: {reason}")
            }
            SigstorePolicy::Audit => {
                tracing::warn!(
                    reference = %reference_str,
                    reason = %reason,
                    "Sigstore verification failed in Audit mode — artifact unattested"
                );
                Ok(false)
            }
            SigstorePolicy::Disabled => unreachable!(),
        },
    }
}

use super::ModuleRegistry;

/// Default namespace within the registry where templates live, e.g.
/// `https://ghcr.io` + `talos-tools` → repos at
/// `ghcr.io/talos-tools/{name}:{tag}`.
const DEFAULT_NAMESPACE: &str = "talos-tools";

/// Tag for the discovery-index artifact.
const INDEX_TAG: &str = "latest";

/// Repo name (within `namespace`) for the discovery-index artifact.
const INDEX_REPO: &str = "_index";

/// Sync interval — long enough that catalog churn doesn't dominate registry
/// traffic, short enough that operator updates land within minutes.
const SYNC_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
struct IndexConfig {
    /// List of templates the operator has published. Each entry is fetched
    /// individually via `pull_manifest_and_config` to get the real talos.json.
    templates: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    /// Repo name within the namespace (e.g. `anthropic-claude`). NOT the
    /// fully-qualified path.
    name: String,
    /// Tag to pull. `latest` is acceptable but a pinned semver tag (`v1.2.3`)
    /// is the production-grade choice.
    tag: String,
}

/// Legacy /v2/_catalog response shape, used only as a discovery fallback.
#[derive(Deserialize)]
struct CatalogResponse {
    repositories: Vec<String>,
}

/// Legacy /v2/{repo}/tags/list response shape, used only with the catalog
/// fallback. MCP-943 (2026-05-15): the `name` field is part of the OCI
/// spec response but we don't read it (we already know the repo we
/// queried). Keep the field for documentation + future use; narrow-scope
/// the dead-code allow so it doesn't mask anything else in the module.
#[derive(Deserialize)]
#[allow(dead_code)]
struct TagsResponse {
    name: String,
    tags: Option<Vec<String>>,
}

pub async fn start_registry_sync_loop(registry: Arc<ModuleRegistry>) {
    // OCI registry sync is opt-in via TALOS_REGISTRY_URL. Without an
    // explicit value, the loop doesn't start — disk-seeded templates from
    // `module-templates/` remain the source of truth.
    //
    // MCP-598 (2026-05-12): empty string is treated as unset to match the
    // controller-side `seed_templates` filter. Without this, a Helm
    // values.yaml placeholder `registryUrl: ""` would shadow BOTH fallback
    // paths — disk seeding skipped (because `env::var` returns `Ok("")`)
    // AND OCI sync failing on every poll trying to parse `""` as a URL —
    // and the pod would come up with no templates at all. Sibling class
    // to MCP-590/591/597 (empty env-var asymmetry).
    let Some(registry_url) = env::var("TALOS_REGISTRY_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        tracing::info!(
            "TALOS_REGISTRY_URL not set — OCI registry sync disabled. \
             Templates will be served from the disk-seeded set only."
        );
        return;
    };

    // MCP-766 (2026-05-13): filter empty so a helm-rendered
    // `TALOS_REGISTRY_NAMESPACE=""` doesn't shadow `DEFAULT_NAMESPACE`.
    // Pre-fix `unwrap_or_else` only fired on env-unset; `Ok("")` from
    // a placeholder value yielded `namespace = ""`, which the
    // downstream `format!("{host}/{namespace}/{repo}:{tag}")` shape
    // (used by every OCI reference in this file — index discovery
    // at line ~221, repo prefix at 338, full ref at 422 + 479)
    // turned into `host//repo:tag` (double-slash). Most OCI registries
    // reject double-slash refs with 404, so template sync silently
    // failed on every iteration with no clear attribution to the
    // misconfigured env var. Same empty-env class as the
    // controller-side `registry_auth_from_env` (already filters
    // empty) and MCP-590..765 sweep. Sibling-helper drift within
    // the SAME file: `registry_auth_from_env` at sync.rs:547 had the
    // right shape; this earlier sweep was missed.
    let namespace = env::var("TALOS_REGISTRY_NAMESPACE")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string());

    let auth = registry_auth_from_env();

    let oci_client = OciClient::new(ClientConfig {
        protocol: client_protocol_for(&registry_url),
        ..Default::default()
    });
    // MCP-1016 (2026-05-15): bound the catalog/tags HTTP client with
    // explicit timeouts. Pre-fix `HttpClient::new()` ran with no
    // request timeout and no connect timeout — a registry that
    // hangs the TCP connection or stops sending bytes mid-response
    // blocks the entire background sync task forever (the outer
    // `loop` at line 145 awaits `sync_once(...).await` serially).
    // Sibling pattern to MCP-533 (Gmail token exchange) and the
    // canonical `.timeout(...).redirect(Policy::none()).build()`
    // shape used across talos-llm / gmail / gcal / atlassian. Keep
    // the default reqwest redirect policy here because OCI
    // registries legitimately 3xx the v2/_catalog response toward
    // blob storage on some providers; the request carries only
    // Basic auth in a header that travels with redirects on the
    // same host, no secret-oracle risk. Loud `.expect()` so a
    // TLS-init failure surfaces immediately instead of silently
    // falling back to `Client::new()` and re-enabling unbounded
    // timeouts.
    // allow-default-redirect: OCI registries legitimately 3xx /v2/_catalog
    // toward blob storage; reqwest strips Authorization on cross-origin
    // redirects, so the Basic-auth header only travels same-host. See the
    // block comment above.
    let http_client = HttpClient::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("Registry sync: failed to build hardened reqwest client");

    // Give the system a few seconds to start up before the first sync —
    // matches the existing behaviour and avoids racing the controller's
    // own HTTP server / DB pool initialisation.
    sleep(Duration::from_secs(5)).await;

    loop {
        tracing::info!(
            registry_url = %registry_url,
            namespace = %namespace,
            "Starting OCI registry sync"
        );
        if let Err(e) = sync_once(
            &oci_client,
            &http_client,
            &registry_url,
            &namespace,
            &auth,
            &registry,
        )
        .await
        {
            tracing::error!("Registry sync failed: {:#}", e);
        }
        sleep(SYNC_INTERVAL).await;
    }
}

/// One sync iteration: discover templates, fetch each manifest+config,
/// upsert into the modules table.
async fn sync_once(
    oci: &OciClient,
    http: &HttpClient,
    registry_url: &str,
    namespace: &str,
    auth: &RegistryAuth,
    db: &ModuleRegistry,
) -> Result<()> {
    let entries = discover_templates(oci, http, registry_url, namespace, auth).await?;
    if entries.is_empty() {
        tracing::info!(
            "OCI registry sync: no templates discovered (registry empty or index not yet published)"
        );
        return Ok(());
    }

    tracing::info!("OCI registry sync: discovered {} templates", entries.len());
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for entry in entries {
        match sync_template(oci, registry_url, namespace, &entry, auth, db).await {
            Ok(()) => succeeded += 1,
            Err(e) => {
                failed += 1;
                tracing::error!(
                    name = %entry.name,
                    tag = %entry.tag,
                    "Failed to sync template: {:#}", e
                );
            }
        }
    }
    tracing::info!(
        "OCI registry sync complete: {} succeeded, {} failed",
        succeeded,
        failed
    );
    Ok(())
}

/// Discover the set of templates to sync. Tries the index artifact first
/// (registry-portable) and falls back to `/v2/_catalog` if absent. Returns
/// an empty list (not an error) when neither is available — that's a
/// brand-new registry with nothing published yet.
async fn discover_templates(
    oci: &OciClient,
    http: &HttpClient,
    registry_url: &str,
    namespace: &str,
    auth: &RegistryAuth,
) -> Result<Vec<IndexEntry>> {
    if let Some(entries) = try_pull_index(oci, registry_url, namespace, auth).await? {
        return Ok(entries);
    }
    tracing::debug!("Index artifact not available — falling back to /v2/_catalog discovery");
    if let Some(entries) = try_v2_catalog(http, registry_url, namespace, auth).await? {
        return Ok(entries);
    }
    Ok(Vec::new())
}

/// Pull the index artifact and parse its config blob into the template list.
/// Returns `Ok(None)` when the artifact doesn't exist (404), `Err` only on
/// real registry errors so the caller can fall back cleanly.
async fn try_pull_index(
    oci: &OciClient,
    registry_url: &str,
    namespace: &str,
    auth: &RegistryAuth,
) -> Result<Option<Vec<IndexEntry>>> {
    let host = strip_scheme(registry_url);
    let reference: Reference = format!("{host}/{namespace}/{INDEX_REPO}:{INDEX_TAG}")
        .parse()
        .context("Construct index Reference")?;

    // H2: verify the index artifact's Sigstore signature BEFORE
    // parsing the config blob. A tampered or MITM'd index could
    // inject malicious template entries (pointing at attacker-
    // controlled image refs); without the signature gate, those
    // entries get persisted to the modules table and become the
    // discovery surface for every operator workflow. The
    // per-template `sync_template` call below ALSO verifies, so
    // this is two layers of attestation: the index itself, and the
    // individual artifacts it advertises. Failures under Audit
    // policy are logged but allowed to proceed (migration window).
    let _index_attested = verify_oci_artifact_signature(&reference)
        .await
        .with_context(|| format!("Sigstore verify _index artifact {reference}"))?;

    match oci.pull_manifest_and_config(&reference, auth).await {
        Ok((_manifest, config_str, _config_digest)) => {
            let parsed: IndexConfig = serde_json::from_str(&config_str)
                .context("Parse _index config blob as IndexConfig JSON")?;
            Ok(Some(parsed.templates))
        }
        Err(e) => {
            // oci_distribution doesn't expose typed 404s — match on the message.
            // This is intentional: most other errors (auth, network) we want to
            // bubble up; a missing index is an expected first-deploy state.
            let msg = format!("{e:#}");
            if is_not_found_error(&msg) {
                tracing::debug!("Index artifact {reference} not found — first deploy?");
                Ok(None)
            } else {
                Err(e).context("pull_manifest_and_config(_index)")
            }
        }
    }
}

/// Fallback discovery via `/v2/_catalog` — only works on self-hosted Docker
/// registries (`registry:2`) and similar. GHCR / GAR / ECR don't expose this.
///
/// L-26: forwards `RegistryAuth::Basic` credentials as an
/// `Authorization: Basic <b64>` header so private self-hosted registries
/// requiring auth are reachable via this fallback path. (Anonymous and
/// bearer-token-flow registries shouldn't expose `/v2/_catalog` to
/// anonymous callers anyway, so the basic-auth case is the realistic
/// missing piece.)
///
/// L-26 (cont.): walks the `Link: <…?n=…&last=…>; rel="next"` header for
/// pagination. Caps at `MAX_CATALOG_PAGES` (200 pages × 1000 entries =
/// 200k repos) to bound time and memory. Beyond that the operator should
/// migrate to the Index artifact path anyway.
async fn try_v2_catalog(
    http: &HttpClient,
    registry_url: &str,
    namespace: &str,
    auth: &RegistryAuth,
) -> Result<Option<Vec<IndexEntry>>> {
    /// Per-page size (registry-default is implementation-specific; ask
    /// for the documented v2 ceiling so we minimise round-trips).
    const PAGE_SIZE: usize = 1000;
    /// Hard upper bound on pages walked. Defence-in-depth: a misbehaving
    /// registry returning a Link loop won't drag us into an infinite
    /// fetch.
    const MAX_CATALOG_PAGES: usize = 200;

    let registry_root = registry_url.trim_end_matches('/').to_string();
    let mut next_url = format!("{registry_root}/v2/_catalog?n={PAGE_SIZE}");
    let mut all_repos: Vec<String> = Vec::new();
    let mut pages_walked = 0usize;

    loop {
        if pages_walked >= MAX_CATALOG_PAGES {
            tracing::warn!(
                pages_walked,
                "v2/_catalog pagination cap hit — stopping. Consider switching to Index artifact discovery."
            );
            break;
        }
        let mut req = http.get(&next_url);
        req = apply_basic_auth(req, auth);
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                if pages_walked == 0 {
                    tracing::debug!("Catalog endpoint unreachable: {e}");
                    return Ok(None);
                }
                tracing::warn!(
                    "Catalog page {pages_walked} fetch failed: {e} — returning partial result"
                );
                break;
            }
        };
        if !resp.status().is_success() {
            if pages_walked == 0 {
                return Ok(None);
            }
            tracing::warn!(
                status = %resp.status(),
                "Catalog page {pages_walked} returned non-success — stopping"
            );
            break;
        }
        // Capture the Link header BEFORE consuming the body via .json().
        let link_header = resp
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let catalog: CatalogResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Parse /v2/_catalog response")?;
        all_repos.extend(catalog.repositories);
        pages_walked += 1;

        // Walk the Link header. Spec form:
        //   Link: </v2/_catalog?n=1000&last=repo>; rel="next"
        // Accept relative paths (most registries) and absolute URLs.
        let Some(link) = link_header.and_then(|hdr| parse_next_link(&hdr)) else {
            break;
        };
        next_url = if link.starts_with("http://") || link.starts_with("https://") {
            link
        } else if let Some(rest) = link.strip_prefix('/') {
            format!("{registry_root}/{rest}")
        } else {
            format!("{registry_root}/{link}")
        };
    }

    let prefix = format!("{namespace}/");
    let index_repo_full = format!("{namespace}/{INDEX_REPO}");
    let mut entries = Vec::new();
    for repo in all_repos {
        if !repo.starts_with(&prefix) || repo == index_repo_full {
            continue;
        }
        let name = repo.trim_start_matches(&prefix).to_string();
        // Fetch tags for this repo.
        let tags_url = format!("{registry_root}/v2/{repo}/tags/list");
        let mut tags_req = http.get(&tags_url);
        tags_req = apply_basic_auth(tags_req, auth);
        let Ok(tags_resp) = tags_req.send().await else {
            continue;
        };
        if !tags_resp.status().is_success() {
            continue;
        }
        let Ok(tags) = talos_http_body::read_json_capped::<TagsResponse>(tags_resp).await else {
            continue;
        };
        for tag in tags.tags.unwrap_or_default() {
            entries.push(IndexEntry {
                name: name.clone(),
                tag,
            });
        }
    }
    Ok(Some(entries))
}

/// Parse a `rel="next"` URL out of an RFC 5988 `Link` header.
///
/// Multi-link form: `<u1>; rel="next", <u2>; rel="prev"`.
/// We only care about the `next` rel; ignore any others.
fn parse_next_link(header: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        // Each part is `<url>; param=value; param=value`.
        let mut segs = part.splitn(2, ';');
        let url_seg = segs.next()?.trim();
        let params = segs.next().unwrap_or("");
        let url = url_seg.strip_prefix('<')?.strip_suffix('>')?.to_string();
        // Match `rel="next"` (or `rel=next`); be permissive on quoting.
        let mut is_next = false;
        for p in params.split(';') {
            let p = p.trim();
            if let Some((k, v)) = p.split_once('=') {
                if k.trim().eq_ignore_ascii_case("rel") {
                    let v = v.trim().trim_matches('"');
                    if v.eq_ignore_ascii_case("next") {
                        is_next = true;
                    }
                }
            }
        }
        if is_next {
            return Some(url);
        }
    }
    None
}

/// L-26 helper: apply Basic-auth credentials to a reqwest builder when
/// the configured `RegistryAuth` provides them. Anonymous / Bearer-flow
/// registries pass through untouched.
fn apply_basic_auth(req: reqwest::RequestBuilder, auth: &RegistryAuth) -> reqwest::RequestBuilder {
    match auth {
        RegistryAuth::Basic(user, pass) => req.basic_auth(user, Some(pass)),
        _ => req,
    }
}

/// Sync a single template: fetch manifest + config blob, parse talos.json,
/// upsert into the modules table.
async fn sync_template(
    oci: &OciClient,
    registry_url: &str,
    namespace: &str,
    entry: &IndexEntry,
    auth: &RegistryAuth,
    db: &ModuleRegistry,
) -> Result<()> {
    let host = strip_scheme(registry_url);
    let repo = format!("{host}/{namespace}/{}", entry.name);
    let reference: Reference = format!("{repo}:{}", entry.tag)
        .parse()
        .with_context(|| format!("Construct Reference for {repo}:{}", entry.tag))?;

    // H2: verify each per-template artifact's Sigstore signature
    // BEFORE pulling and persisting its config blob. Catalog sync
    // can't trust the index alone — each individual artifact is a
    // separate attestation. Required policy fails the whole
    // template sync; Audit policy logs and continues (the worker
    // still re-verifies at execution time, so Audit is a real
    // migration window).
    let _template_attested = verify_oci_artifact_signature(&reference)
        .await
        .with_context(|| format!("Sigstore verify template artifact {reference}"))?;

    let (_manifest, config_str, _config_digest) = oci
        .pull_manifest_and_config(&reference, auth)
        .await
        .with_context(|| format!("pull_manifest_and_config({reference})"))?;

    let talos_manifest: serde_json::Value =
        serde_json::from_str(&config_str).context("Config blob is not valid JSON")?;

    let name = match talos_manifest
        .get("display_name")
        .or_else(|| talos_manifest.get("name"))
        .and_then(|v| v.as_str())
    {
        Some(n) => n,
        None => {
            tracing::warn!(
                "Skipping {}:{} — manifest config has no name/display_name field",
                entry.name,
                entry.tag
            );
            return Ok(());
        }
    };

    let category = talos_manifest
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("Custom");
    let description = talos_manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let default_schema = serde_json::json!({ "type": "object", "properties": {} });
    let config_schema = talos_manifest
        .get("config_schema")
        .cloned()
        .unwrap_or(default_schema);

    let allowed_hosts: Vec<String> = string_array(&talos_manifest, "allowed_hosts");
    if let Err(msg) = super::validate_allowed_hosts(&allowed_hosts) {
        anyhow::bail!(
            "Invalid allowed_hosts for {}:{}: {}",
            entry.name,
            entry.tag,
            msg
        );
    }
    let allowed_secrets: Vec<String> = string_array(&talos_manifest, "requires_secrets");
    // MCP-1124: validate allowed_secrets at the OCI ingest boundary too.
    // Sibling sweep of MCP-1123 — both `allowed_hosts` and
    // `allowed_secrets` come from the same untrusted upstream OCI
    // manifest and need the same validator-at-boundary discipline.
    if let Err(msg) = super::validate_allowed_secrets(&allowed_secrets) {
        anyhow::bail!(
            "Invalid allowed_secrets for {}:{}: {}",
            entry.name,
            entry.tag,
            msg
        );
    }
    let requires_approval_for: Vec<String> = string_array(&talos_manifest, "requires_approval_for");

    // Same OCI URL format the worker expects.
    let oci_url = format!(
        "oci://{host}/{namespace}/{}:{}",
        entry.name.to_lowercase().replace(' ', "-"),
        entry.tag
    );

    sqlx::query(
        "INSERT INTO modules ( \
             user_id, name, kind, category, description, config_schema, source_code, oci_url, \
             allowed_hosts, allowed_secrets, requires_approval_for, \
             language, created_at, updated_at \
         ) \
         VALUES ( \
             NULL, $1, 'catalog', $2, $3, $4, '', $5, \
             $6, $7, $8, \
             'rust', NOW(), NOW() \
         ) \
         ON CONFLICT (name) WHERE user_id IS NULL DO UPDATE SET \
             category               = EXCLUDED.category, \
             description            = EXCLUDED.description, \
             config_schema          = EXCLUDED.config_schema, \
             oci_url                = EXCLUDED.oci_url, \
             allowed_hosts          = EXCLUDED.allowed_hosts, \
             allowed_secrets        = EXCLUDED.allowed_secrets, \
             requires_approval_for  = EXCLUDED.requires_approval_for, \
             updated_at             = NOW()",
    )
    .bind(name)
    .bind(category)
    .bind(description)
    .bind(&config_schema)
    .bind(&oci_url)
    .bind(&allowed_hosts)
    .bind(&allowed_secrets)
    .bind(&requires_approval_for)
    .execute(&db.db_pool)
    .await
    .context("Upsert into modules")?;

    tracing::debug!("Synced {} from OCI registry", name);
    Ok(())
}

fn string_array(manifest: &serde_json::Value, key: &str) -> Vec<String> {
    manifest
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn strip_scheme(url: &str) -> &str {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}

fn client_protocol_for(url: &str) -> ClientProtocol {
    if url.starts_with("http://") {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    }
}

fn registry_auth_from_env() -> RegistryAuth {
    match (
        env::var("OCI_REGISTRY_USERNAME"),
        env::var("OCI_REGISTRY_PASSWORD"),
    ) {
        (Ok(user), Ok(pass)) if !user.is_empty() && !pass.is_empty() => {
            RegistryAuth::Basic(user, pass)
        }
        _ => RegistryAuth::Anonymous,
    }
}

/// L-25: tightened matcher to reduce false positives.
///
/// Pre-fix: any error string containing "404" anywhere matched (e.g. a
/// stack trace mentioning `port :404`, or a `ECONNREFUSED to host:404`)
/// would be misclassified and silently fall through to the legacy
/// `/v2/_catalog` discovery path. The new matcher requires `404` to
/// be flanked by whitespace/punctuation OR to follow `: ` so it only
/// matches HTTP-status-formatted occurrences.
///
/// `manifest_unknown` is OCI-distribution's spec-defined "missing
/// artifact" code and remains a strong positive signal. The literal
/// phrase "not found" must appear bounded by word boundaries so e.g.
/// "service not foundation" doesn't match.
fn is_not_found_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();

    if lower.contains("manifest_unknown") {
        return true;
    }

    // HTTP status: ": 404 " or " 404 " or "(404)" — but NOT "host:404"
    // or numbers that happen to contain 404.
    let http_404 = lower.contains(": 404 ")
        || lower.contains(" 404 ")
        || lower.contains("(404)")
        || lower.ends_with(" 404")
        || lower.starts_with("404 ");
    if http_404 {
        return true;
    }

    // Word-bounded "not found": preceded by start/whitespace, followed
    // by end/whitespace/punct. Cheap two-substring check covers the
    // common HTTP-status-text shapes ("404 Not Found", "Not Found",
    // "manifest not found") without matching "not foundation".
    if let Some(idx) = lower.find("not found") {
        let after_idx = idx + "not found".len();
        let trailing = lower.as_bytes().get(after_idx);
        let is_terminator = match trailing {
            None => true,
            Some(b) => matches!(
                *b,
                b' ' | b'\t'
                    | b'\n'
                    | b'\r'
                    | b':'
                    | b'.'
                    | b','
                    | b';'
                    | b')'
                    | b']'
                    | b'"'
                    | b'\''
            ),
        };
        if is_terminator {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_scheme_handles_all_forms() {
        assert_eq!(strip_scheme("https://ghcr.io"), "ghcr.io");
        assert_eq!(strip_scheme("http://registry:5000/"), "registry:5000");
        assert_eq!(strip_scheme("ghcr.io"), "ghcr.io");
    }

    #[test]
    fn client_protocol_picks_http_for_local() {
        assert!(matches!(
            client_protocol_for("http://registry:5000"),
            ClientProtocol::Http
        ));
        assert!(matches!(
            client_protocol_for("https://ghcr.io"),
            ClientProtocol::Https
        ));
    }

    #[test]
    fn auth_falls_back_to_anonymous_on_blank_creds() {
        std::env::remove_var("OCI_REGISTRY_USERNAME");
        std::env::remove_var("OCI_REGISTRY_PASSWORD");
        assert!(matches!(registry_auth_from_env(), RegistryAuth::Anonymous));
    }

    #[test]
    fn not_found_detection_covers_common_phrasings() {
        assert!(is_not_found_error("server returned 404 Not Found"));
        assert!(is_not_found_error("MANIFEST_UNKNOWN: tag latest not found"));
        assert!(is_not_found_error("got 404 from upstream"));
        assert!(!is_not_found_error("server returned 500"));
        assert!(!is_not_found_error("connection refused"));
    }

    #[test]
    fn not_found_rejects_404_in_port_or_substring() {
        // L-25 regression guards: pre-fix these all returned true.
        assert!(!is_not_found_error("ECONNREFUSED to host:404"));
        assert!(!is_not_found_error("error 4040: gateway"));
        assert!(!is_not_found_error("got 14040 something"));
        // "not foundation" must NOT match
        assert!(!is_not_found_error("the service had no found foundation"));
    }

    #[test]
    fn not_found_accepts_explicit_status_formats() {
        assert!(is_not_found_error("HTTP 404"));
        assert!(is_not_found_error("status: (404)"));
        assert!(is_not_found_error("Not Found."));
    }

    #[test]
    fn index_config_round_trip() {
        let raw = serde_json::json!({
            "templates": [
                {"name": "anthropic-claude", "tag": "v1.0.0"},
                {"name": "http-request", "tag": "v2.1.3"}
            ]
        });
        let parsed: IndexConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.templates.len(), 2);
        assert_eq!(parsed.templates[0].name, "anthropic-claude");
        assert_eq!(parsed.templates[1].tag, "v2.1.3");
    }

    #[test]
    fn parse_next_link_extracts_simple_next() {
        let h = r#"</v2/_catalog?n=1000&last=foo>; rel="next""#;
        assert_eq!(
            parse_next_link(h),
            Some("/v2/_catalog?n=1000&last=foo".to_string())
        );
    }

    #[test]
    fn parse_next_link_picks_next_among_multiple_rels() {
        let h = r#"</v2/_catalog?n=1000&last=a>; rel="next", </v2/_catalog>; rel="prev""#;
        assert_eq!(
            parse_next_link(h),
            Some("/v2/_catalog?n=1000&last=a".to_string())
        );
    }

    #[test]
    fn parse_next_link_unquoted_rel() {
        let h = r#"</v2/_catalog?last=z>; rel=next"#;
        assert_eq!(parse_next_link(h), Some("/v2/_catalog?last=z".to_string()));
    }

    #[test]
    fn parse_next_link_no_next_rel_returns_none() {
        let h = r#"</v2/_catalog>; rel="prev""#;
        assert_eq!(parse_next_link(h), None);
    }

    #[test]
    fn parse_next_link_handles_absolute_url() {
        let h = r#"<https://registry.example.com/v2/_catalog?n=1000&last=x>; rel="next""#;
        assert_eq!(
            parse_next_link(h),
            Some("https://registry.example.com/v2/_catalog?n=1000&last=x".to_string())
        );
    }

    #[test]
    fn parse_next_link_malformed_returns_none() {
        // Missing angle brackets.
        assert_eq!(parse_next_link("/v2/_catalog?n=1000; rel=\"next\""), None);
        // Empty header.
        assert_eq!(parse_next_link(""), None);
    }
}
