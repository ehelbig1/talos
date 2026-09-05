use anyhow::Result;
use async_nats::jetstream::{self, stream::Config as StreamConfig, Message};
use async_nats::Client;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    primitives::{ByteStream, DateTime as S3DateTime},
    Client as S3Client,
};
use chrono::Utc;
use futures::stream::StreamExt;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
// `pub use` so consumers (e.g. the talos-api GraphQL admin query) can name the
// report types without a direct dep on talos-audit-event.
pub use talos_audit_event::{
    audit_verify_keys, verify_chain, AuditEvent, ChainBreak, ChainVerificationReport,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Outcome of inline per-message audit verification (finding #2, Layer 1).
enum VerifyOutcome {
    /// Persist the event. `unsigned` is true when no HMAC was present but
    /// verification keys ARE configured — anomalous in steady state (logged
    /// loudly) but NOT rejected, per the producer's "missing signature =
    /// unverified, not invalid" contract for the pre-signing migration window.
    Accept { unsigned: bool },
    /// Positive tamper/corruption evidence — do NOT persist to the ledger;
    /// the message is quarantined instead.
    Reject(&'static str),
}

/// Verify a single audit message before persistence (finding #2, Layer 1 —
/// the stateless authenticity check). Two independent checks:
///   1. **Integrity** — re-derive the event hash canonically (via the shared
///      `talos_audit_event` code, so it can't drift from the producer) and
///      confirm it equals the published `hash`. Catches transport corruption
///      or a doctored `hash` field.
///   2. **Authenticity** — verify the HMAC-SHA256 signature against the
///      configured keys. Catches a forged/altered event from anyone without
///      the signing key.
///
/// The STATEFUL completeness check (sequence contiguity, chain linkage) is
/// deliberately NOT here — it needs the full ordered record set and runs
/// offline via [`talos_audit_event::verify_chain`].
///
/// Counts `talos_audit_verification_failures_total{stage="event"}` on every
/// `Reject`. The count lives HERE rather than at the quarantine site below
/// because this is the whole classification, it has exactly one production
/// caller (the ingest batch loop), and it is directly unit-testable — the
/// quarantine site sits inside a NATS+Postgres batch handler that no test can
/// drive. A future second caller MUST be a real verification decision, not a
/// dry run, or it will inflate a CRITICAL alert.
fn verify_audit_message(
    event_value: &Value,
    published_hash: Option<&str>,
    keys: &[Vec<u8>],
) -> VerifyOutcome {
    let outcome = classify_audit_message(event_value, published_hash, keys);
    if matches!(outcome, VerifyOutcome::Reject(_)) {
        inc_audit_verification_failure(AUDIT_STAGE_EVENT);
    }
    outcome
}

/// Stage label values for `talos_audit_verification_failures_total`. A closed
/// set of `&'static str`: `event` is the inline per-message check at ingest,
/// `chain` the offline hash-chain sweep. No execution id, workflow id, reject
/// reason or event content is ever a label — `reason` in particular is bounded
/// today but lives next to caller-shaped data, and the alert routes on stage.
pub(crate) const AUDIT_STAGE_EVENT: &str = "event";
pub(crate) const AUDIT_STAGE_CHAIN: &str = "chain";

/// Count one audit-verification failure. Inert (never unwraps) when
/// `talos_metrics::set_global` has not run, per the `talos_metrics::global`
/// contract. Written by hand at both stages rather than through a shared
/// warn-and-count macro — see the detector-metrics block in
/// `talos_metrics::TalosMetrics` for why a macro would re-blind check 58.
fn inc_audit_verification_failure(stage: &'static str) {
    if let Some(m) = talos_metrics::global() {
        m.audit_verification_failures_total
            .with_label_values(&[stage])
            .inc();
    }
}

/// The verification decision itself, split from [`verify_audit_message`] so the
/// counter has one exit point instead of one per `Reject` return.
fn classify_audit_message(
    event_value: &Value,
    published_hash: Option<&str>,
    keys: &[Vec<u8>],
) -> VerifyOutcome {
    let event: AuditEvent = match serde_json::from_value(event_value.clone()) {
        Ok(e) => e,
        Err(_) => return VerifyOutcome::Reject("event_deserialize_failed"),
    };
    let recomputed = event.calculate_hash();
    match published_hash {
        Some(h) if h == recomputed => {}
        _ => return VerifyOutcome::Reject("hash_mismatch"),
    }
    match event.verify_signature(keys) {
        Some(true) => VerifyOutcome::Accept { unsigned: false },
        Some(false) => VerifyOutcome::Reject("bad_signature"),
        // Unsigned: only anomalous when keys are configured.
        None => VerifyOutcome::Accept {
            unsigned: !keys.is_empty(),
        },
    }
}

// ── OTLP auth-header encryption ────────────────────────────────────────────────
//
// The per-tenant OTLP streaming auth headers are sealed with the canonical
// SecretsManager v3 envelope: a KEK-backed DEK (unwrapped through whatever
// KekProvider is configured — env OR Vault transit) + a per-context HKDF subkey
// + the tenant's `user_id` bound as AAD. This is the SAME envelope every other
// AAD-bound column uses, so it carries no bespoke crypto and — critically — does
// NOT depend on the env master key: a Vault-only deployment that has dropped
// TALOS_MASTER_KEY still encrypts and decrypts these headers.
//
// Write path: `talos-api` update_audit_settings → `encrypt_otlp_auth_headers`.
// Read path: `OTLPCache::get_tracer` → `SecretsManager::decrypt_versioned`,
// keyed on the stored `auth_headers_enc_key_id` + `auth_headers_format`. The
// `user_id` AAD means a DB-write attacker can't transpose one tenant's header
// blob into another's `user_audit_settings` row and have it decrypt.
//
// (The earlier bespoke env-master-key HKDF scheme was removed once it had no
// rows to support — there is exactly one encryption path now.)

/// Envelope encrypt for OTLP auth headers via [`SecretsManager`] — the
/// KEK-backed path that does **not** depend on the env master key. The DEK is
/// unwrapped through whatever `KekProvider` is configured (env OR Vault
/// transit), so a Vault-only deployment that has dropped `TALOS_MASTER_KEY`
/// can still encrypt the per-tenant headers.
///
/// Per-org DEK arc: writes format v4 — per-context key derived from the owning
/// user's PERSONAL-org root DEK (OTLP audit settings are per-user;
/// `user_audit_settings` is user-keyed). Decrypt is unchanged — `get_tracer`'s
/// `decrypt_versioned` routes v4 through the same per-context derived path as v3
/// (the row's `auth_headers_enc_key_id` names the org DEK). Existing v3 rows
/// keep decrypting.
///
/// Returns `(key_id, ciphertext_blob, format_version)` for the
/// `auth_headers_enc_key_id` / `auth_headers_encrypted` / `auth_headers_format`
/// columns. The blob is `[12-byte nonce][AES-256-GCM ciphertext+tag]` — the
/// nonce is embedded in the blob, never stored separately. AAD = the owning
/// tenant's `user_id` bytes, so a blob can't be transposed between tenants.
///
/// [`SecretsManager`]: talos_secrets_manager::SecretsManager
pub async fn encrypt_otlp_auth_headers(
    secrets_manager: &talos_secrets_manager::SecretsManager,
    plaintext: &str,
    user_id: Uuid,
) -> Result<(Uuid, Vec<u8>, i16), String> {
    secrets_manager
        .encrypt_value_aad_v4_for_user(plaintext, user_id, user_id.as_bytes())
        .await
        .map_err(|e| format!("OTLP auth-header encrypt failed: {e}"))
}

/// S3 Object-Lock retention applied per audit batch upload when
/// `TALOS_AUDIT_S3_OBJECT_LOCK=true`. The bucket MUST have Object Lock
/// enabled at creation time (it cannot be toggled on existing buckets);
/// when enabled here without bucket-side support, S3 returns
/// `InvalidRequest` and the batch will be redelivered indefinitely.
///
/// `Compliance` mode is intentional: retained objects cannot be removed
/// even by an account root user until the retention date. This is the
/// stronger of the two Object Lock modes and the right default for
/// tamper-evident audit storage. Use `Governance` only if regulatory
/// allowance for an early-removal escape hatch is acceptable — Talos
/// does not currently expose that knob.
#[derive(Clone, Copy, Debug)]
struct ObjectLockConfig {
    /// Days of retention from the moment of upload. Bounded to
    /// [1, 36500] (100 years) at parse time to prevent operator typos
    /// from creating effectively-permanent retention by accident.
    retention_days: i64,
}

/// Pure parser exposed for unit testing. The env-driven entry point
/// `load_object_lock_config` reads `TALOS_AUDIT_S3_OBJECT_LOCK` and
/// `TALOS_AUDIT_S3_RETENTION_DAYS` and delegates here so the validation
/// logic (kill-switch flag, days bounded to [1, 36500], default 7 years)
/// can be tested without env mutation.
fn parse_object_lock_config(
    enabled_var: Option<&str>,
    retention_var: Option<&str>,
) -> Option<ObjectLockConfig> {
    if enabled_var != Some("true") {
        return None;
    }
    let retention_days = retention_var
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&d| (1..=36500).contains(&d))
        .unwrap_or(2555); // 7 years default — tracks SOX / HIPAA / SOC2 norms.
    Some(ObjectLockConfig { retention_days })
}

fn load_object_lock_config() -> Option<ObjectLockConfig> {
    let enabled = std::env::var("TALOS_AUDIT_S3_OBJECT_LOCK").ok();
    let retention = std::env::var("TALOS_AUDIT_S3_RETENTION_DAYS").ok();
    let cfg = parse_object_lock_config(enabled.as_deref(), retention.as_deref());
    if let Some(c) = &cfg {
        tracing::info!(
            retention_days = c.retention_days,
            mode = "Compliance",
            "Audit S3 Object Lock ENABLED — bucket must have Object Lock enabled at creation"
        );
    }
    cfg
}

#[cfg(test)]
mod object_lock_parse_tests {
    use super::parse_object_lock_config;

    #[test]
    fn disabled_when_env_missing() {
        assert!(parse_object_lock_config(None, None).is_none());
    }

    #[test]
    fn disabled_when_env_not_true() {
        assert!(parse_object_lock_config(Some("false"), None).is_none());
        assert!(parse_object_lock_config(Some(""), None).is_none());
        assert!(
            parse_object_lock_config(Some("1"), None).is_none(),
            "must require literal 'true' — '1' is a common operator typo"
        );
    }

    #[test]
    fn defaults_to_seven_years_when_enabled_no_retention() {
        let cfg = parse_object_lock_config(Some("true"), None).expect("enabled");
        assert_eq!(cfg.retention_days, 2555);
    }

    #[test]
    fn honors_explicit_retention_within_bounds() {
        let cfg = parse_object_lock_config(Some("true"), Some("365")).expect("enabled");
        assert_eq!(cfg.retention_days, 365);
    }

    #[test]
    fn rejects_zero_retention() {
        let cfg = parse_object_lock_config(Some("true"), Some("0")).expect("enabled");
        assert_eq!(
            cfg.retention_days, 2555,
            "0 is invalid — must fall back to default rather than create a no-retention lock"
        );
    }

    #[test]
    fn rejects_negative_retention() {
        let cfg = parse_object_lock_config(Some("true"), Some("-1")).expect("enabled");
        assert_eq!(cfg.retention_days, 2555);
    }

    #[test]
    fn rejects_excessive_retention_above_100_years() {
        let cfg = parse_object_lock_config(Some("true"), Some("36501")).expect("enabled");
        assert_eq!(
            cfg.retention_days, 2555,
            "operator typos like 36500*10 should not produce effectively-permanent locks"
        );
    }

    #[test]
    fn rejects_unparseable_retention() {
        let cfg = parse_object_lock_config(Some("true"), Some("seven_years")).expect("enabled");
        assert_eq!(cfg.retention_days, 2555);
    }
}

use lru::LruCache;
use opentelemetry::{
    trace::{Span, Status, Tracer, TracerProvider as _},
    KeyValue,
};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Cache of OTLP Exporters per Tenant
struct OTLPCache {
    providers: Mutex<LruCache<Uuid, SdkTracerProvider>>,
}

impl OTLPCache {
    fn new() -> Self {
        Self {
            providers: Mutex::new(LruCache::new(
                NonZeroUsize::new(100).expect("100 is non-zero"),
            )),
        }
    }

    async fn get_tracer(
        &self,
        user_id: Uuid,
        pool: &PgPool,
        secrets_manager: Option<&talos_secrets_manager::SecretsManager>,
    ) -> Option<opentelemetry_sdk::trace::Tracer> {
        // Check cache first
        {
            let mut providers = self.providers.lock().await;
            if let Some(provider) = providers.get(&user_id) {
                return Some(provider.clone().tracer("talos-audit-exporter"));
            }
        }

        // Fetch settings from DB. MCP-948 (2026-05-15): `otlp_protocol`
        // is deserialised from the column but not consumed yet —
        // settings.otlp_protocol has no reader (the audit exporter
        // currently builds gRPC unconditionally). Kept in the
        // SettingsRow for documentation + future protocol-selection
        // wiring; narrow-scope the dead-code allow so other dead
        // surface in this file still warns.
        #[derive(sqlx::FromRow)]
        #[allow(dead_code)]
        struct SettingsRow {
            streaming_enabled: bool,
            otlp_endpoint: Option<String>,
            otlp_protocol: Option<String>,
            auth_headers_encrypted: Option<Vec<u8>>,
            // v3 envelope columns: the DEK id + AAD format version.
            auth_headers_enc_key_id: Option<Uuid>,
            auth_headers_format: i16,
        }
        let settings = sqlx::query_as::<_, SettingsRow>(
            r#"
            SELECT streaming_enabled, otlp_endpoint, otlp_protocol,
                   auth_headers_encrypted,
                   auth_headers_enc_key_id, auth_headers_format
            FROM user_audit_settings
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await;

        // #661 (error-as-absence): `.ok()??` collapsed three different
        // outcomes into one `None` — "streaming is off for this user", "this
        // user has no settings row", and "the settings row could not be READ".
        // Only the first two are configuration. The third silently disables a
        // user's audit streaming for the lifetime of the DB fault, and audit
        // streaming going quiet is precisely the failure an audit trail must
        // not be able to hide. This function returns `Option` and its callers
        // treat `None` as "no exporter", so the fallback is unchanged — what
        // changes is that the read failure is now distinguishable in the log
        // rather than looking like a deliberate opt-out.
        let settings = match settings {
            Ok(row) => row?,
            Err(e) => {
                tracing::warn!(
                    target: "talos_audit",
                    user_id = %user_id,
                    error = %e,
                    event_kind = "audit_settings_read_failed",
                    "could not READ user_audit_settings — audit streaming is being \
                     skipped for this user because the row was unreadable, NOT because \
                     streaming is disabled; batches are buffered, not sent"
                );
                return None;
            }
        };

        if !settings.streaming_enabled {
            return None;
        }

        let endpoint = settings.otlp_endpoint?;

        // MCP-792 (2026-05-14): re-validate the OTLP endpoint at fire time.
        // MCP-773 added the write-time SSRF gate to the GraphQL
        // `update_audit_settings` mutation but explicitly deferred fire-time
        // re-validation ("the write-time check alone closes the direct-IP-
        // literal abuse surface, which is the dominant exploitation path").
        // This adds defense-in-depth: a malicious endpoint persisted via
        // direct SQL UPDATE (bypassing the GraphQL gate) — or any future
        // write-side validation bypass — would otherwise reach
        // `SpanExporter::builder().with_endpoint(endpoint).build()` below
        // and the audit subsystem would dispatch outbound gRPC to user-
        // supplied internal targets on every batch. Cheap syntactic
        // re-check (no DNS); falls closed on rejection by returning None,
        // so `get_tracer` skips the exporter build and audit batches for
        // that user are buffered rather than sent. Does NOT close the
        // DNS-rebinding gap (would require DNS pinning, since Tonic
        // re-resolves at connect time) — that remains a deferred follow-up.
        // Pre-fix the only check between write and use was sqlx's bind
        // safety; mutation paths outside the GraphQL mutation (admin
        // shell, migration backfill, direct psql access) had no gate.
        if let Err(reason) = talos_http_utils::ssrf::check_outbound_url_no_ssrf(&endpoint) {
            tracing::warn!(
                target: "talos_audit",
                user_id = %user_id,
                reason = %reason,
                "OTLP endpoint failed fire-time SSRF re-check — refusing to build exporter. \
                 This is defense-in-depth against write-side bypasses; check the user_audit_settings \
                 row and the audit trail of update_audit_settings calls for this user."
            );
            return None;
        }

        let mut metadata = tonic::metadata::MetadataMap::new();

        if let Some(encrypted) = settings.auth_headers_encrypted {
            // Decrypt the SecretsManager v3 envelope (KEK-backed DEK + per-context
            // HKDF subkey + user_id AAD). Do NOT silently swallow failures — a
            // decrypt error means the exporter would stream WITHOUT auth, which
            // operators must be able to see.
            let decrypted: Result<Zeroizing<String>, String> =
                match (settings.auth_headers_enc_key_id, secrets_manager) {
                    (Some(key_id), Some(sm)) => sm
                        .decrypt_versioned(
                            key_id,
                            &encrypted,
                            user_id.as_bytes(),
                            settings.auth_headers_format,
                        )
                        .await
                        .map_err(|e| format!("v3 envelope decrypt failed: {e}")),
                    (Some(_), None) => Err("no SecretsManager is wired into the audit \
                         subscriber — cannot decrypt OTLP auth headers"
                        .to_string()),
                    (None, _) => Err("auth_headers_encrypted is present but \
                         auth_headers_enc_key_id is NULL (corrupt or pre-v3 row)"
                        .to_string()),
                };

            match decrypted {
                Ok(json_str) => match serde_json::from_str::<HashMap<String, String>>(&json_str) {
                    Ok(json_headers) => {
                        for (k, v) in json_headers {
                            if let (Ok(key), Ok(val)) = (
                                k.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>(),
                                v.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>(),
                            ) {
                                metadata.insert(key, val);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "talos_audit",
                            user_id = %user_id,
                            "OTLP auth headers decrypted but are not a valid JSON string map: {e} \
                             — exporter will stream WITHOUT auth headers"
                        );
                    }
                },
                Err(reason) => {
                    tracing::warn!(
                        target: "talos_audit",
                        user_id = %user_id,
                        reason = %reason,
                        "Failed to decrypt OTLP auth headers — exporter will stream WITHOUT auth \
                         headers. Check the KEK provider (env/Vault) the SecretsManager is wired \
                         to, then re-save via update_audit_settings."
                    );
                }
            }
        }

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_metadata(metadata)
            .build()
            .ok()?;

        // otel 0.28+: runtime-agnostic batch processor (no runtime arg) and
        // builder-based `Resource` (`Resource::new` was removed).
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_attributes(vec![
                        KeyValue::new("service.name", "talos-audit-stream"),
                        KeyValue::new("tenant.id", user_id.to_string()),
                    ])
                    .build(),
            )
            .build();

        let tracer = provider.tracer("talos-audit-exporter");

        let mut providers = self.providers.lock().await;
        providers.put(user_id, provider);

        Some(tracer)
    }
}

/// Non-secret `user_audit_settings` row for the GraphQL `auditSettings`
/// query. Deliberately EXCLUDES the encrypted OTLP auth-header columns —
/// this shape is for display surfaces; the exporter path
/// ([`OTLPCache::get_tracer`]) reads + decrypts them itself.
#[derive(Debug, sqlx::FromRow)]
pub struct UserAuditSettingsRow {
    pub streaming_enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub otlp_protocol: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Fetch a user's audit settings (non-secret columns). Pool-taking so the
/// GraphQL resolver runs it on its context pool; the table is user-keyed,
/// not org-pinned RLS, so a bare pool is the correct executor.
pub async fn get_user_audit_settings(
    pool: &PgPool,
    user_id: Uuid,
) -> anyhow::Result<Option<UserAuditSettingsRow>> {
    let row = sqlx::query_as::<_, UserAuditSettingsRow>(
        r#"
        SELECT streaming_enabled, otlp_endpoint, otlp_protocol, created_at, updated_at
        FROM user_audit_settings
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Parameters for [`upsert_user_audit_settings`]. The auth-header fields are
/// the pre-encrypted envelope triple from [`encrypt_otlp_auth_headers`] —
/// this function never sees plaintext headers.
#[derive(Debug)]
pub struct UserAuditSettingsUpsert {
    pub user_id: Uuid,
    pub streaming_enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub otlp_protocol: Option<String>,
    pub auth_headers_encrypted: Option<Vec<u8>>,
    pub auth_headers_enc_key_id: Option<Uuid>,
    pub auth_headers_format: i16,
}

/// Upsert a user's audit settings (keyed on user_id). Pool-taking; the table
/// is user-keyed, not org-pinned RLS, so a bare pool is the correct executor.
/// Caller is responsible for endpoint validation (SSRF gate) and header
/// encryption BEFORE calling.
pub async fn upsert_user_audit_settings(
    pool: &PgPool,
    s: UserAuditSettingsUpsert,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO user_audit_settings (
            user_id, streaming_enabled, otlp_endpoint, otlp_protocol,
            auth_headers_encrypted,
            auth_headers_enc_key_id, auth_headers_format, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            streaming_enabled = EXCLUDED.streaming_enabled,
            otlp_endpoint = EXCLUDED.otlp_endpoint,
            otlp_protocol = EXCLUDED.otlp_protocol,
            auth_headers_encrypted = EXCLUDED.auth_headers_encrypted,
            auth_headers_enc_key_id = EXCLUDED.auth_headers_enc_key_id,
            auth_headers_format = EXCLUDED.auth_headers_format
            /* updated_at deliberately NOT set: the BEFORE UPDATE trigger stamps it
               only when a column really changed (migration 20260905120000). A
               block comment, not `--`: a line comment survives only while the
               newlines do. */
        "#,
    )
    .bind(s.user_id)
    .bind(s.streaming_enabled)
    .bind(s.otlp_endpoint)
    .bind(s.otlp_protocol)
    .bind(s.auth_headers_encrypted)
    .bind(s.auth_headers_enc_key_id)
    .bind(s.auth_headers_format)
    .execute(pool)
    .await?;
    Ok(())
}

/// Build the optional S3 client for the WORM audit bucket from env.
///
/// Endpoint resolution: `AWS_ENDPOINT_URL`, then `MINIO_ENDPOINT` (empty
/// strings treated as unset — the helm-placeholder class fixed in
/// MCP-934). Path-style addressing via `AWS_S3_FORCE_PATH_STYLE` (MinIO).
/// `None` when no endpoint is configured. Shared by the subscriber (write
/// path) and [`verify_execution_chain`] (read path) so the (endpoint,
/// path-style) resolution can never drift between them.
pub async fn build_audit_s3_client() -> Option<S3Client> {
    let s3_endpoint = std::env::var("AWS_ENDPOINT_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("MINIO_ENDPOINT")
                .ok()
                .filter(|v| !v.is_empty())
        })?;
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let mut builder = aws_sdk_s3::config::Builder::from(&config).endpoint_url(s3_endpoint);
    // MCP-1073: canonical bool-env helper (accepts 1/yes/on/TRUE), required
    // for MinIO which needs path-style addressing.
    if talos_config::bool_env_or_default("AWS_S3_FORCE_PATH_STYLE", false) {
        builder = builder.force_path_style(true);
    }
    Some(S3Client::from_conf(builder.build()))
}

/// The WORM audit bucket name (`MINIO_BUCKET`, default `audit-logs`). Empty
/// is treated as unset (MCP-653).
pub fn audit_bucket_name() -> String {
    std::env::var("MINIO_BUCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "audit-logs".to_string())
}

/// Convenience entry point for an admin/audit caller (an operator endpoint
/// or a periodic sweep): build the S3 client from env and verify the
/// persisted chain for one execution. Errors when no S3 endpoint is
/// configured (the chain has no durable store to read).
pub async fn verify_execution_chain_from_env(
    workflow_id: &str,
    execution_id: &str,
) -> Result<ChainVerificationReport> {
    let client = build_audit_s3_client().await.ok_or_else(|| {
        anyhow::anyhow!(
            "no audit S3 endpoint configured (set AWS_ENDPOINT_URL or MINIO_ENDPOINT) — \
             the WORM chain has no durable store to verify"
        )
    })?;
    let bucket = audit_bucket_name();
    verify_execution_chain(&client, &bucket, workflow_id, execution_id).await
}

/// Tally from one [`run_chain_verification_sweep`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChainSweepStats {
    /// Executions queried (terminal + within the window + cap).
    pub scanned: usize,
    /// Chains that verified with no breaks.
    pub verified_ok: usize,
    /// Chains WITH breaks — tamper / corruption / gap / linkage / bad HMAC.
    pub failed: usize,
    /// Executions whose chain could not be read (S3/IO error) — unverified.
    pub errored: usize,
    /// The row cap bound: there were AT LEAST `scanned` executions in the
    /// window and the oldest of them were not verified.
    ///
    /// # Why this is not merely a disclosure
    ///
    /// The sweep takes `ORDER BY completed_at DESC ... LIMIT max_executions`
    /// over a SLIDING `[now-lookback, now-settle]` window, and keeps NO cursor,
    /// watermark or offset — `ChainSweepStats` is rebuilt from `default()` on
    /// every pass. So the rows the cap drops are the OLDEST in the window; by
    /// the next tick they are older still and fall out the back. **They are
    /// never verified by any later pass.**
    ///
    /// Meanwhile `failed == 0 && errored == 0` is trivially satisfied by rows
    /// nobody looked at, so before 2026-08-19 the controller logged
    /// "audit chain verification sweep completed clean" as a bill of health over
    /// a window it had not finished — on a SECURITY assurance. An attacker who
    /// breaks a chain and then generates more than `max_executions` completions
    /// inside one window would earn a permanent, unqualified "clean" for that
    /// break.
    ///
    /// This flag does not fix the coverage gap — closing that needs a cursor, or
    /// a lookback the operator has sized against their completion rate. It stops
    /// the gap being reported as a clean bill of health, which is the difference
    /// between an unverified window and a window falsely certified.
    pub cap_hit: bool,
}

/// Periodic sweep that runs the offline chain verifier over recently-completed
/// executions and emits a loud structured event for any break (finding #2).
/// This is what makes the WORM ledger **continuously** verified rather than
/// only on demand — it runs as a trusted controller-side system task, so it
/// needs no per-tenant scoping and no MCP/RBAC surface.
///
/// Scope: terminal executions (`completed`/`failed`/`cancelled`) whose
/// `completed_at` falls in `[now - lookback, now - settle]`, newest first,
/// capped at `max_executions`. The `settle` floor avoids false "sequence gap"
/// reports on executions whose audit events are still being batched to S3 (the
/// consumer flushes every few seconds) — only chains old enough to be fully
/// flushed are checked. Run the sweep on an interval that overlaps the lookback
/// window slightly so nothing at a boundary is missed; re-verification is
/// idempotent and cheap.
pub async fn run_chain_verification_sweep(
    db_pool: &PgPool,
    s3_client: &S3Client,
    bucket: &str,
    lookback_secs: i64,
    settle_secs: i64,
    max_executions: i64,
) -> ChainSweepStats {
    let mut stats = ChainSweepStats::default();

    // `INTERVAL '1 second' * $N` (not make_interval) — the int4-only
    // make_interval args don't apply, and this form takes a bigint bind.
    // Unique ORDER BY tiebreaker (id) per the pagination-stability rule.
    let rows = match sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, workflow_id \
         FROM workflow_executions \
         WHERE status IN ('completed', 'failed', 'cancelled') \
           AND completed_at IS NOT NULL \
           AND completed_at <= NOW() - (INTERVAL '1 second' * $1) \
           AND completed_at >= NOW() - (INTERVAL '1 second' * $2) \
         ORDER BY completed_at DESC, id DESC \
         LIMIT $3",
    )
    .bind(settle_secs)
    .bind(lookback_secs)
    .bind(max_executions)
    .fetch_all(db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                target: "talos_audit",
                event_kind = "audit_chain_sweep_query_failed",
                error = %e,
                "audit chain sweep could not enumerate executions — skipping this pass"
            );
            return stats;
        }
    };

    stats.scanned = rows.len();
    // `>=` for the safe direction: a window holding exactly the cap is
    // indistinguishable from one holding more, and the alternative is a sweep
    // that quietly certifies a short window.
    stats.cap_hit = max_executions > 0 && rows.len() as i64 >= max_executions;
    for (exec_id, wf_id) in rows {
        let outcome =
            verify_execution_chain(s3_client, bucket, &wf_id.to_string(), &exec_id.to_string())
                .await;
        record_chain_verification_outcome(&mut stats, outcome, exec_id, wf_id);
    }
    stats
}

/// Fold ONE chain-verification result into the sweep stats, the operator log,
/// and `talos_audit_verification_failures_total{stage="chain"}`.
///
/// Split out of [`run_chain_verification_sweep`]'s loop so the classification
/// (and therefore the counter wiring) is unit-testable — the loop itself needs
/// both Postgres and an S3/WORM endpoint, so nothing could drive it. What this
/// does NOT prove is that the sweep still CALLS it; that residual is one line
/// above, and the honest guard for it is the post-merge live check.
///
/// Only a chain WITH BREAKS counts. An S3/IO error is `errored`, not `failed`:
/// "could not read the chain" is not evidence of tampering, and counting it
/// would make an object-store blip page as a compliance incident (#578 —
/// unverifiable is not the same as verified-bad). The counter is deliberately
/// NOT incremented by the on-demand
/// [`verify_execution_chain_from_env`] operator path either, so repeatedly
/// re-checking one known-broken chain cannot re-page.
fn record_chain_verification_outcome(
    stats: &mut ChainSweepStats,
    outcome: Result<ChainVerificationReport>,
    exec_id: Uuid,
    wf_id: Uuid,
) {
    match outcome {
        Ok(report) if report.ok => stats.verified_ok += 1,
        Ok(report) => {
            stats.failed += 1;
            inc_audit_verification_failure(AUDIT_STAGE_CHAIN);
            // The security signal — one ERROR per broken chain so SIEM
            // can alert per execution. `breaks` is a structured list.
            tracing::error!(
                target: "talos_audit",
                event_kind = "audit_chain_verification_failed",
                execution_id = %exec_id,
                workflow_id = %wf_id,
                total_events = report.total_events,
                signatures_checked = report.signatures_checked,
                breaks = ?report.breaks,
                "audit chain verification FAILED for a completed execution — \
                 possible tampering, deletion, reorder, or corruption"
            );
        }
        Err(e) => {
            stats.errored += 1;
            tracing::warn!(
                target: "talos_audit",
                event_kind = "audit_chain_verification_errored",
                execution_id = %exec_id,
                workflow_id = %wf_id,
                error = %e,
                "could not verify an execution's audit chain (S3/IO) — left unverified"
            );
        }
    }
}

/// Convenience wrapper: build the S3 client + bucket from env and run
/// [`run_chain_verification_sweep`]. Returns `None` (and logs once at DEBUG)
/// when no S3 endpoint is configured, so the caller can spawn it
/// unconditionally — it self-disables without a WORM store.
pub async fn run_chain_verification_sweep_from_env(
    db_pool: &PgPool,
    lookback_secs: i64,
    settle_secs: i64,
    max_executions: i64,
) -> Option<ChainSweepStats> {
    let Some(client) = build_audit_s3_client().await else {
        tracing::debug!(
            target: "talos_audit",
            "audit chain verification sweep skipped — no S3 endpoint configured"
        );
        return None;
    };
    let bucket = audit_bucket_name();
    Some(
        run_chain_verification_sweep(
            db_pool,
            &client,
            &bucket,
            lookback_secs,
            settle_secs,
            max_executions,
        )
        .await,
    )
}

pub async fn start_audit_ledger_subscriber(
    nc: Client,
    db_pool: PgPool,
    secrets_manager: Option<Arc<talos_secrets_manager::SecretsManager>>,
) -> Result<()> {
    tracing::info!("Initializing audit ledger subscriber");
    tracing::debug!("Audit ledger subscriber initialisation proceeding");

    let js = jetstream::new(nc);

    // Ensure the stream exists for guaranteed delivery
    let stream_name = "AUDIT_LEDGER";
    let subject = talos_workflow_job_protocol::subjects::AUDIT_LEDGER;
    let _stream = js
        .get_or_create_stream(StreamConfig {
            name: stream_name.to_string(),
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await?;

    // MCP-1119 (2026-05-16): consumer + messages-stream creation
    // moved INSIDE the supervisor loop below. Pre-fix they were
    // created once here and the inner loop's stream-end branch
    // (`None` at line ~428) broke out of the loop, the spawned
    // task exited, and the audit subsystem went OFFLINE until
    // controller restart — the explicit "real fix is a supervisor"
    // deferral noted at MCP-570. Initial validation that we CAN
    // create the consumer is performed below as the first
    // supervisor iteration; startup failures still log+retry but
    // no longer fail-fast at this point (NATS-transient errors
    // during pod startup shouldn't crash the whole controller).

    // Initialise optional S3 client.
    //
    // MCP-514: pre-fix this block called `std::env::set_var` from
    // inside an async task to redirect AWS_ENDPOINT_URL → MINIO_ENDPOINT
    // when the AWS form was absent. Mutating process-global env from a
    // multi-threaded async context races with any concurrent
    // `std::env::var()` read (the AWS SDK's `load_defaults` runs many
    // such reads, including on background threads it spawns), and the
    // mutation persists for the rest of the process — corrupting env
    // for unrelated code that reads AWS_ENDPOINT_URL afterward. Rust
    // 2024 edition made `set_var` `unsafe` precisely because of this
    // class. The fix is to pass the endpoint explicitly to the SDK
    // builder via `endpoint_url(...)` instead of going through env.
    // MCP-934 (2026-05-15): filter empty-string env values so the
    // `.or_else` MINIO_ENDPOINT fallback actually fires when the
    // primary env is set-but-empty. Pre-fix `AWS_ENDPOINT_URL=""`
    // (a common Helm placeholder pattern when an operator hasn't
    // configured the real endpoint) returned `Ok("")` → `.ok()`
    // yielded `Some("")` → `or_else` was skipped → the empty
    // string propagated into `aws_sdk_s3::config::Builder::
    // endpoint_url("")`. The AWS SDK then either rejects the
    // request at first use or silently routes to a default
    // endpoint, defeating the MinIO-fallback intent.
    //
    // Same empty-env-var-bypass class as MCP-590/591/597/598/599/
    // 615/653/710 etc. Single canonical fix shape: `.filter(|v|
    // !v.is_empty())` after each `.ok()`. Resolution + path-style logic
    // lives in `build_audit_s3_client` so the offline verifier reads from
    // the exact same bucket the subscriber writes to.
    let s3_client: Option<S3Client> = build_audit_s3_client().await;

    tracing::info!(
        "Audit ledger subscriber ready – S3 client {}",
        if s3_client.is_some() {
            "configured"
        } else {
            "not configured"
        }
    );

    // Resolve Object-Lock policy ONCE at startup (not per-batch). Operator
    // changes to TALOS_AUDIT_S3_OBJECT_LOCK require a controller restart —
    // intentional: Object Lock is a security boundary, not a feature flag,
    // and runtime toggling would create gaps in the tamper-evident chain.
    let object_lock = load_object_lock_config();

    tokio::spawn(async move {
        tracing::info!("🔒 Started WORM Cryptographic Ledger subscriber on 'talos.audit.ledger'");
        let otlp_cache = Arc::new(OTLPCache::new());

        // MCP-653: empty-env class. `MINIO_BUCKET: ""` (helm placeholder)
        // previously produced `bucket = ""`, which the S3 client rejected
        // at upload time — every WORM audit-log batch silently failed
        // until the operator noticed. Treat empty as unset. Same fix
        // shape as MCP-630/631.
        let bucket = audit_bucket_name();
        let max_batch_size = 100;

        // MCP-1119 (2026-05-16): supervisor loop that re-binds the
        // pull consumer + messages stream when JetStream ends the
        // stream (NATS reconnect, consumer expiry, server restart).
        // Pre-fix the inner loop's `None` arm `break`'d out, the
        // spawned task exited, and the audit subsystem went OFFLINE
        // until controller restart — events accumulated in
        // JetStream until ack_wait timeout, then redelivered to a
        // fresh subscriber on next restart. The MCP-570 comment
        // explicitly deferred this fix; this commit closes it.
        //
        // Backoff caps at 60s — long enough to avoid hot-looping
        // against a persistently broken NATS, short enough that
        // audit downtime is bounded.
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
            // (Re-)create consumer + messages stream. `get_or_create_consumer`
            // is idempotent on the durable_name so re-creation across
            // supervisor iterations binds to the SAME persistent state
            // (no message loss across re-binds).
            let consumer = match _stream
                .get_or_create_consumer(
                    "audit_ledger_processor",
                    async_nats::jetstream::consumer::pull::Config {
                        durable_name: Some("audit_ledger_processor".to_string()),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(
                        target: "talos_audit_ledger",
                        event_kind = "audit_consumer_bind_failed",
                        error = %e,
                        backoff_secs,
                        "Audit ledger JetStream consumer bind failed; retrying after backoff"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue 'supervisor;
                }
            };
            let mut messages = match consumer.messages().await {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(
                        target: "talos_audit_ledger",
                        event_kind = "audit_messages_stream_failed",
                        error = %e,
                        backoff_secs,
                        "Audit ledger messages stream creation failed; retrying after backoff"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue 'supervisor;
                }
            };
            // Reset backoff on successful bind — next stream-end
            // restart starts at 1s again.
            backoff_secs = 1;
            let mut batch: Vec<Message> = Vec::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            // Inner work loop. Exits via `break` on stream-end
            // (None arm); supervisor will re-bind.
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, secrets_manager.as_deref(), object_lock).await;
                        }
                    }
                    msg_result = messages.next() => {
                        match msg_result {
                            Some(Ok(msg)) => {
                                batch.push(msg);
                                if batch.len() >= max_batch_size {
                                    process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, secrets_manager.as_deref(), object_lock).await;
                                    interval.reset();
                                }
                            }
                            Some(Err(e)) => {
                                tracing::error!("Error receiving message from JetStream: {}", e);
                            }
                            None => {
                                // Stream ended (NATS reconnect, consumer
                                // expiry, server restart). Flush any
                                // pending batch, log loudly so the
                                // supervisor's re-bind is operator-
                                // visible, then break out so the
                                // outer 'supervisor loop re-binds.
                                if !batch.is_empty() {
                                    process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, secrets_manager.as_deref(), object_lock).await;
                                }
                                tracing::warn!(
                                    target: "talos_audit_ledger",
                                    event_kind = "audit_consumer_stream_end_rebinding",
                                    backoff_secs = 1,
                                    "Audit ledger JetStream consumer stream ended — supervisor will re-bind (no controller restart required)"
                                );
                                break;
                            }
                        }
                    }
                }
            }
            // Inner loop broke → supervisor re-binds after a
            // short pause. Don't sleep on the first re-bind
            // attempt (backoff_secs was reset to 1 above), but
            // sleep 1s to avoid a tight loop if the stream
            // immediately ends again.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(())
}

async fn process_batch(
    batch: &mut Vec<Message>,
    s3_client: &Option<S3Client>,
    bucket: &str,
    db_pool: &PgPool,
    otlp_cache: &Arc<OTLPCache>,
    secrets_manager: Option<&talos_secrets_manager::SecretsManager>,
    object_lock: Option<ObjectLockConfig>,
) {
    if batch.is_empty() {
        return;
    }

    tracing::debug!("Processing WORM batch of {} audit messages", batch.len());

    let mut invalid_messages = Vec::new();
    // Finding #2, Layer 1: messages that fail cryptographic verification.
    // (idx, reason, execution_id) — quarantined to S3, never persisted to
    // the ledger, never ACK-dropped silently.
    let mut rejected_messages: Vec<(usize, &'static str, String)> = Vec::new();
    let mut grouped_messages: HashMap<String, Vec<(Value, usize)>> = HashMap::new();

    // Verification keys (current + previous), loaded once per batch. Empty
    // when signing is disabled — then HMAC checks are skipped (events are
    // persisted as "unverified") but the hash-integrity check still runs.
    let verify_keys = talos_audit_event::audit_verify_keys();

    // MCP-808 (2026-05-14): pre-pass + batch user_id lookup. Pre-fix the
    // per-message loop below ran up to TWO `WHERE id = $1` round-trips per
    // audit event (workflow_executions, then module_executions on miss) —
    // a classic N+1 against tables that may be hot for the controller's
    // request path. At 100 msg/batch every 5 s under load, that's up to
    // 200 DB queries every tick (40 qps overhead just to resolve the
    // OTLP user_id, most of which the per-message OTLP cache then
    // discards because the user has no `streaming_enabled` row).
    //
    // Fix: parse every message ONCE into a typed intermediate, collect
    // distinct workflow_ids across the whole batch, then issue exactly
    // TWO batched `WHERE id = ANY($1)` queries (workflow_executions
    // first, module_executions for the remainder). Per-message lookup
    // becomes a `HashMap::get` against the prefetched map. CLAUDE.md
    // performance rule: "NEVER use N+1 query patterns. Batch with
    // `WHERE id = ANY($1)` when processing collections." This is the
    // canonical fix shape.
    //
    // The intermediate also lets us drop the double-parse cost we'd
    // otherwise need to inspect each message twice.

    struct ParsedMsg {
        idx: usize,
        wrapper: Value,
        execution_id: String,
        workflow_id: String,
        workflow_uuid: Option<Uuid>,
    }

    let mut parsed: Vec<ParsedMsg> = Vec::with_capacity(batch.len());
    for (idx, msg) in batch.iter().enumerate() {
        match serde_json::from_slice::<Value>(&msg.payload) {
            Ok(wrapper) => {
                if wrapper.get("event").is_some() {
                    let event = wrapper.get("event").expect("just checked");
                    let execution_id = event["execution_id"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let workflow_id = event["workflow_id"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let workflow_uuid = Uuid::parse_str(&workflow_id).ok();

                    // Finding #2, Layer 1: verify BEFORE persisting. A
                    // verification failure is positive tamper/corruption
                    // evidence — quarantine it (loud ERROR + retained bytes),
                    // never silently drop, never persist to the ledger.
                    let published_hash = wrapper.get("hash").and_then(|h| h.as_str());
                    let seq = event["sequence_num"].as_u64().unwrap_or(0);
                    match verify_audit_message(event, published_hash, &verify_keys) {
                        VerifyOutcome::Accept { unsigned } => {
                            if unsigned {
                                tracing::error!(
                                    target: "talos_audit",
                                    event_kind = "audit_event_unsigned",
                                    execution_id = %execution_id,
                                    sequence_num = seq,
                                    "audit event carries no HMAC signature but signing keys ARE \
                                     configured — persisting as UNVERIFIED (possible signature \
                                     strip, or a pre-signing event still in flight)"
                                );
                            }
                            parsed.push(ParsedMsg {
                                idx,
                                wrapper,
                                execution_id,
                                workflow_id,
                                workflow_uuid,
                            });
                        }
                        VerifyOutcome::Reject(reason) => {
                            tracing::error!(
                                target: "talos_audit",
                                event_kind = "audit_event_verification_failed",
                                reason,
                                execution_id = %execution_id,
                                sequence_num = seq,
                                "audit event FAILED cryptographic verification — quarantining, \
                                 NOT persisting to the ledger. This is a tamper/corruption signal."
                            );
                            rejected_messages.push((idx, reason, execution_id));
                        }
                    }
                } else {
                    // MCP-921 (2026-05-14): drop `{:?}` Debug-dump of
                    // the unparsed wrapper. Pre-fix this WARN-level
                    // log fired the entire raw audit payload (workflow
                    // event JSON: log_message, output_payload, possibly
                    // raw API responses that escaped DLP) whenever a
                    // publisher to `talos.audit.events` sent a message
                    // without the `event` wrapper. Same `{:?}` over
                    // user-controlled content class as MCP-852/853/854
                    // (which swept talos-api, talos-mcp-handlers,
                    // talos-engine but didn't reach this crate). The
                    // diagnostic value is "what shape did the
                    // unrecognised payload have?" — top-level field
                    // names are schema (safe to log); values are data
                    // (not safe). Project to keys-only so operators
                    // can still chase the misconfigured publisher.
                    let top_level_fields: Vec<&str> = wrapper
                        .as_object()
                        .map(|m| m.keys().map(String::as_str).collect())
                        .unwrap_or_default();
                    tracing::warn!(
                        target: "talos_audit",
                        top_level_fields = ?top_level_fields,
                        "Audit message missing 'event' object — dropping"
                    );
                    invalid_messages.push(idx);
                }
            }
            Err(_) => {
                tracing::warn!("Received unparseable audit ledger message. Dropping poison pill.");
                invalid_messages.push(idx);
            }
        }
    }

    // Phase 2: batch-resolve user_ids for distinct workflow_ids in this batch.
    let distinct_wids: HashSet<Uuid> = parsed.iter().filter_map(|p| p.workflow_uuid).collect();
    let mut user_id_map: HashMap<Uuid, Uuid> = HashMap::new();
    if !distinct_wids.is_empty() {
        let wids_vec: Vec<Uuid> = distinct_wids.iter().copied().collect();
        match sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT id, user_id FROM workflow_executions WHERE id = ANY($1)",
        )
        .bind(&wids_vec)
        .fetch_all(db_pool)
        .await
        {
            Ok(rows) => {
                for (id, uid) in rows {
                    user_id_map.insert(id, uid);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_audit",
                    error = %e,
                    "Batch lookup against workflow_executions failed — OTLP streaming may be skipped this batch"
                );
            }
        }
        let missing: Vec<Uuid> = wids_vec
            .iter()
            .copied()
            .filter(|id| !user_id_map.contains_key(id))
            .collect();
        if !missing.is_empty() {
            match sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT id, user_id FROM module_executions WHERE id = ANY($1)",
            )
            .bind(&missing)
            .fetch_all(db_pool)
            .await
            {
                Ok(rows) => {
                    for (id, uid) in rows {
                        user_id_map.insert(id, uid);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "talos_audit",
                        error = %e,
                        "Batch lookup against module_executions failed — OTLP streaming may be skipped for module-id-keyed events this batch"
                    );
                }
            }
        }
    }

    // Phase 3: process each parsed message using the prefetched map.
    for ParsedMsg {
        idx,
        wrapper,
        execution_id,
        workflow_id,
        workflow_uuid,
    } in parsed
    {
        let event = wrapper
            .get("event")
            .expect("ParsedMsg guarantees event presence");
        let user_id_opt = workflow_uuid.and_then(|wid| user_id_map.get(&wid).copied());

        // OTLP Streaming (The BYOD Feature)
        if let Some(user_id) = user_id_opt {
            if let Some(tracer) = otlp_cache
                .get_tracer(user_id, db_pool, secrets_manager)
                .await
            {
                let mut span = tracer.start("audit_event");
                span.set_attribute(KeyValue::new("talos.workflow.id", workflow_id.clone()));
                span.set_attribute(KeyValue::new("talos.execution.id", execution_id.clone()));
                span.set_attribute(KeyValue::new(
                    "talos.crypto.sequence",
                    event["sequence_num"].as_u64().unwrap_or(0) as i64,
                ));
                // The actor identifier (e.g. "human:manager@company.com" or
                // "agent:gpt-4") is exported to the tenant's OWN OTLP collector
                // for trace attribution — the operator-email PII is intentional
                // tenant-scoped telemetry. Run it through `redact_str` anyway
                // for consistency with the sibling `talos.payload` attribute
                // below: defense-in-depth so a secret-shaped value that ever
                // lands in the actor field (e.g. a misformatted "agent:sk-...")
                // doesn't egress to the collector in the clear. That stated
                // consistency is why this one moved to `redact_span_text` at
                // the same time as its sibling — leaving it on the bare,
                // failsafe-less `redact_str` would have made the comment false
                // the moment the sibling changed.
                span.set_attribute(KeyValue::new(
                    "talos.actor",
                    talos_trace::redact_span_text(event["actor"].as_str().unwrap_or("unknown"))
                        .into_owned(),
                ));
                span.set_attribute(KeyValue::new(
                    "talos.action",
                    event["action"].as_str().unwrap_or("unknown").to_string(),
                ));
                if let Some(hash) = wrapper.get("hash").and_then(|h| h.as_str()) {
                    span.set_attribute(KeyValue::new("talos.crypto.hash", hash.to_string()));
                }
                if let Some(prev) = event.get("previous_hash").and_then(|h| h.as_str()) {
                    span.set_attribute(KeyValue::new(
                        "talos.crypto.previous_hash",
                        prev.to_string(),
                    ));
                }
                // ORDERING FIX (supersedes MCP-1207's truncate-then-redact).
                //
                // MCP-1207 clipped `event["payload"]` to 4 KiB and redacted the
                // clip, to bound the regex pass over what can be a ~1 MB NATS
                // message. That ordering leaks: the AWS pattern is
                // `\bA[KS]IA[0-9A-Z]{16}\b`, so a key straddling byte 4096 is
                // cut, stops matching entirely, and its surviving prefix is
                // exported unredacted. `redact_str` also has no failsafe — a
                // panic inside the redactor propagates instead of yielding
                // `REDACTION_UNAVAILABLE`.
                //
                // `talos_trace::redact_span_text` is the single span-text sink
                // helper introduced by #650: redact FIRST, bound SECOND, panic
                // ⇒ placeholder. Delegating removes the ordering decision from
                // this site rather than re-deciding it correctly here — there
                // is no second redactor to drift.
                //
                // Two consequences, stated rather than buried. (1) The preview
                // bound becomes `MAX_SPAN_TEXT_CHARS` (2000 Unicode scalars,
                // the platform-wide span-text bound) instead of 4096 bytes;
                // still far inside every known OTLP per-attribute limit, which
                // was MCP-1207's other stated reason for clipping. (2) The
                // redaction pass now covers the whole payload, which is what
                // MCP-1207 was avoiding. That is a single linear
                // finite-automaton pass (the `regex` crate does not backtrack),
                // paid only on an audit append with a tracer configured — i.e.
                // never on a deployment with trace export off. Correctness over
                // the micro-optimisation.
                let payload_str = event["payload"].as_str().unwrap_or("");
                span.set_attribute(KeyValue::new(
                    "talos.payload",
                    talos_trace::redact_span_text(payload_str).into_owned(),
                ));
                span.set_status(Status::Ok);
                span.end();
            }
        }

        let hash = wrapper
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        tracing::info!(
            "WORM_LEDGER_APPEND [{}] Seq: {} | Actor: {} | Action: {} | Hash: {}",
            execution_id,
            event["sequence_num"].as_u64().unwrap_or(0),
            event["actor"].as_str().unwrap_or("unknown"),
            event["action"].as_str().unwrap_or("unknown"),
            hash
        );

        grouped_messages
            .entry(execution_id)
            .or_default()
            .push((wrapper, idx));
    }

    let mut successful_indices = Vec::new();
    let mut failed_indices = Vec::new();

    if let Some(client) = s3_client {
        for (execution_id, items) in grouped_messages {
            let mut payload_bytes = Vec::new();
            let mut min_seq = u64::MAX;
            let mut max_seq = 0;
            let mut current_indices = Vec::new();

            for (wrapper, idx) in items {
                let seq = wrapper
                    .get("event")
                    .and_then(|e| e.get("sequence_num"))
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);
                if seq < min_seq {
                    min_seq = seq;
                }
                if seq > max_seq {
                    max_seq = seq;
                }

                if let Ok(mut bytes) = serde_json::to_vec(&wrapper) {
                    bytes.push(b'\n'); // JSON-Lines format
                                       // Guard: skip oversized individual messages (>1 MB) to prevent
                                       // a single large event from blowing up the S3 upload buffer.
                    if bytes.len() > 1_048_576 {
                        tracing::warn!(
                            idx = idx,
                            size = bytes.len(),
                            "Audit message exceeds 1 MB — skipping to protect upload buffer"
                        );
                        failed_indices.push(idx);
                        continue;
                    }
                    // Guard: cap total batch payload at 100 MB.
                    if payload_bytes.len() + bytes.len() > 104_857_600 {
                        tracing::warn!(
                            idx = idx,
                            "Audit batch payload would exceed 100 MB — skipping remaining messages for this execution"
                        );
                        failed_indices.push(idx);
                        continue;
                    }
                    payload_bytes.extend(bytes);
                    current_indices.push(idx);
                }
            }

            if min_seq > max_seq {
                min_seq = 0;
            }

            let key = format!(
                "{}/{}_{}_{}.jsonl",
                execution_id,
                min_seq,
                max_seq,
                Utc::now()
                    .timestamp_nanos_opt()
                    .unwrap_or_else(|| Utc::now().timestamp())
            );

            // Build the request, conditionally adding Object-Lock fields.
            // We compute the retain-until date per-batch (not per-loop) so a
            // delayed batch carries a retention window measured from upload
            // time, not from the worker's startup. retain_until_date is in
            // epoch seconds — `aws_smithy_types::DateTime::from_secs` is the
            // canonical conversion. Compliance mode means even root cannot
            // remove the object until expiry — the right default for an
            // immutable audit ledger.
            let mut put = client
                .put_object()
                .bucket(bucket)
                .key(&key)
                .body(ByteStream::from(payload_bytes));
            if let Some(lock) = object_lock {
                let retain_until = chrono::Utc::now() + chrono::Duration::days(lock.retention_days);
                put = put
                    .object_lock_mode(aws_sdk_s3::types::ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(S3DateTime::from_secs(retain_until.timestamp()));
            }
            match put.send().await {
                Ok(_) => {
                    tracing::debug!(
                        "Persisted batched audit events to bucket {} with key {}",
                        bucket,
                        key
                    );
                    successful_indices.extend(current_indices);
                }
                Err(e) => {
                    tracing::error!("Failed to persist batched audit events to {}: {}", key, e);
                    failed_indices.extend(current_indices);
                }
            }
        }
    } else {
        // If S3 is not configured, we consider all parsed messages successful
        for (_, items) in grouped_messages {
            for (_, idx) in items {
                successful_indices.push(idx);
            }
        }
    }

    // Finding #2, Layer 1: quarantine verification-failed messages to a
    // dedicated `rejected/` S3 prefix (Object-Locked like the ledger) so the
    // tamper/corruption evidence is RETAINED, not dropped into the void the
    // way the pre-fix silent ACK did. Best-effort: a quarantine-write failure
    // is itself logged loudly; the structured ERROR emitted at detection time
    // is the durable SIEM signal regardless. We ACK afterwards so a
    // permanently-bad message can't wedge the stream in a redelivery loop.
    if !rejected_messages.is_empty() {
        if let Some(client) = s3_client {
            for (idx, reason, execution_id) in &rejected_messages {
                let Some(msg) = batch.get(*idx) else { continue };
                let key = format!(
                    "rejected/{}/{}_{}_{}.json",
                    execution_id,
                    reason,
                    Utc::now()
                        .timestamp_nanos_opt()
                        .unwrap_or_else(|| Utc::now().timestamp()),
                    idx
                );
                let mut put = client
                    .put_object()
                    .bucket(bucket)
                    .key(&key)
                    .body(ByteStream::from(msg.payload.to_vec()));
                if let Some(lock) = object_lock {
                    let retain_until =
                        chrono::Utc::now() + chrono::Duration::days(lock.retention_days);
                    put = put
                        .object_lock_mode(aws_sdk_s3::types::ObjectLockMode::Compliance)
                        .object_lock_retain_until_date(S3DateTime::from_secs(
                            retain_until.timestamp(),
                        ));
                }
                if let Err(e) = put.send().await {
                    tracing::error!(
                        target: "talos_audit",
                        event_kind = "audit_event_quarantine_failed",
                        reason = *reason,
                        execution_id = %execution_id,
                        error = %e,
                        "failed to quarantine a verification-rejected audit message to S3 — \
                         the rejection ERROR above is the durable signal"
                    );
                }
            }
        }
        tracing::error!(
            target: "talos_audit",
            event_kind = "audit_batch_rejections",
            rejected = rejected_messages.len(),
            "quarantined {} audit message(s) that failed cryptographic verification",
            rejected_messages.len()
        );
    }

    // Acknowledge all processed messages: valid+persisted, structurally-invalid
    // (no `event` wrapper / unparseable), AND verification-rejected (already
    // quarantined). All are terminal — ACK so they don't block the stream.
    let mut all_to_ack = invalid_messages;
    all_to_ack.extend(successful_indices);
    all_to_ack.extend(rejected_messages.iter().map(|(idx, _, _)| *idx));

    for idx in all_to_ack {
        if let Some(msg) = batch.get(idx) {
            if let Err(e) = msg.ack().await {
                tracing::error!("Failed to acknowledge NATS message: {}", e);
            }
        }
    }

    if !failed_indices.is_empty() {
        tracing::warn!(
            "{} messages failed to process and were not acknowledged, will be redelivered",
            failed_indices.len()
        );
    }

    // Clear the batch so we start fresh. Failed messages remain unacknowledged
    // and JetStream will automatically redeliver them after the ack_wait timeout.
    batch.clear();
}

// ============================================================================
// Offline chain verification — S3 reader (finding #2, Layer 2)
// ============================================================================

/// Hard cap on `.jsonl` objects scanned per execution, so a pathological /
/// adversarial execution id can't make the verifier read unboundedly.
const MAX_CHAIN_OBJECTS: usize = 50_000;
/// Hard cap on events assembled for one verification, bounding memory.
const MAX_CHAIN_EVENTS: usize = 5_000_000;

/// Parse the persisted `.jsonl` object bodies into [`AuditEvent`]s. Each line
/// is a `{ "event": <AuditEvent>, "hash": ... }` wrapper (the same shape
/// `process_batch` writes); the `event` object is extracted and typed. Lines
/// that don't parse are skipped with a WARN — a malformed line is itself a
/// finding the chain check will surface as a gap. Pure: unit-testable without S3.
fn extract_events_from_jsonl(objects: &[Vec<u8>]) -> Vec<AuditEvent> {
    let mut events = Vec::new();
    for body in objects {
        for line in body.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if events.len() >= MAX_CHAIN_EVENTS {
                tracing::warn!(
                    target: "talos_audit",
                    cap = MAX_CHAIN_EVENTS,
                    "audit chain verification hit the event cap — report is over a truncated prefix"
                );
                return events;
            }
            match serde_json::from_slice::<Value>(line) {
                Ok(wrapper) => {
                    if let Some(ev) = wrapper.get("event") {
                        match serde_json::from_value::<AuditEvent>(ev.clone()) {
                            Ok(e) => events.push(e),
                            Err(e) => tracing::warn!(
                                target: "talos_audit",
                                error = %e,
                                "skipping a persisted ledger line whose event failed to deserialize"
                            ),
                        }
                    }
                }
                Err(e) => tracing::warn!(
                    target: "talos_audit",
                    error = %e,
                    "skipping an unparseable persisted ledger line"
                ),
            }
        }
    }
    events
}

/// Offline verification of a persisted audit chain for one execution
/// (finding #2, Layer 2 — the stateful completeness check). Reads every
/// `<execution_id>/*.jsonl` object from the WORM bucket, reassembles the
/// events, and runs [`talos_audit_event::verify_chain`] over the full ordered
/// set with the configured verification keys.
///
/// This is the deliberately-offline counterpart to the inline per-message
/// check ([`verify_audit_message`]): it detects sequence gaps (deletion /
/// never-persisted events), broken `previous_hash` linkage (reorder /
/// substitution), genesis mismatch, and per-event HMAC failures — the checks
/// that need the whole record set and so cannot live in the streaming
/// persister. Intended to back an operator/admin audit endpoint or a periodic
/// sweep; safe to call on demand.
pub async fn verify_execution_chain(
    s3_client: &S3Client,
    bucket: &str,
    workflow_id: &str,
    execution_id: &str,
) -> Result<ChainVerificationReport> {
    let prefix = format!("{execution_id}/");
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut continuation: Option<String> = None;
    let mut object_count = 0usize;

    loop {
        let mut req = s3_client.list_objects_v2().bucket(bucket).prefix(&prefix);
        if let Some(token) = &continuation {
            req = req.continuation_token(token);
        }
        let page = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("list_objects_v2 failed for {prefix}: {e}"))?;

        for obj in page.contents() {
            let Some(key) = obj.key() else { continue };
            if object_count >= MAX_CHAIN_OBJECTS {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id,
                    cap = MAX_CHAIN_OBJECTS,
                    "audit chain verification hit the object cap — report is over a truncated prefix"
                );
                break;
            }
            object_count += 1;
            let got = s3_client
                .get_object()
                .bucket(bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("get_object failed for {key}: {e}"))?;
            let bytes = got
                .body
                .collect()
                .await
                .map_err(|e| anyhow::anyhow!("reading body of {key} failed: {e}"))?
                .into_bytes();
            bodies.push(bytes.to_vec());
        }

        match page.next_continuation_token() {
            Some(t) if object_count < MAX_CHAIN_OBJECTS => continuation = Some(t.to_string()),
            _ => break,
        }
    }

    let events = extract_events_from_jsonl(&bodies);
    let keys = audit_verify_keys();
    Ok(verify_chain(workflow_id, execution_id, &events, &keys))
}

#[cfg(test)]
mod chain_reader_tests {
    use super::*;
    use talos_audit_event::{ChainBreak, ExecutionLedger};

    /// Serialize a chain into `.jsonl` object bodies the way `process_batch`
    /// persists them (`{ "event": ..., "hash": ... }` per line), optionally
    /// split across multiple objects, to exercise the parse+reassemble path.
    fn jsonl_objects(events: &[AuditEvent], chunk: usize) -> Vec<Vec<u8>> {
        events
            .chunks(chunk.max(1))
            .map(|group| {
                let mut body = Vec::new();
                for e in group {
                    let wrapper = serde_json::json!({ "event": e, "hash": e.calculate_hash() });
                    body.extend(serde_json::to_vec(&wrapper).unwrap());
                    body.push(b'\n');
                }
                body
            })
            .collect()
    }

    fn chain(n: u64) -> Vec<AuditEvent> {
        let mut l = ExecutionLedger::new("wf", "ex");
        (1..=n)
            .map(|i| l.append("worker", "act", &format!("p{i}")))
            .collect()
    }

    #[test]
    fn reassembles_and_verifies_valid_chain_across_objects() {
        let events = chain(7);
        let objects = jsonl_objects(&events, 3); // 3 objects
        let parsed = extract_events_from_jsonl(&objects);
        assert_eq!(parsed.len(), 7);
        let report = verify_chain("wf", "ex", &parsed, &[]);
        assert!(report.ok, "breaks: {:?}", report.breaks);
    }

    #[test]
    fn detects_a_missing_object_as_a_gap() {
        let events = chain(6);
        let mut objects = jsonl_objects(&events, 2); // 3 objects of 2 events
        objects.remove(1); // drop the object holding seq 3,4
        let parsed = extract_events_from_jsonl(&objects);
        let report = verify_chain("wf", "ex", &parsed, &[]);
        assert!(!report.ok);
        assert!(report
            .breaks
            .iter()
            .any(|b| matches!(b, ChainBreak::SequenceGap { .. })));
    }

    #[test]
    fn skips_malformed_lines_without_panicking() {
        let mut objects = jsonl_objects(&chain(2), 5);
        objects.push(b"not json at all\n{}\n".to_vec());
        let parsed = extract_events_from_jsonl(&objects);
        assert_eq!(parsed.len(), 2); // the two valid events survive
    }
}

#[cfg(test)]
mod inline_verify_tests {
    //! Finding #2, Layer 1: per-message verify-at-persist verdicts. The
    //! canonical hash/HMAC logic itself is tested in `talos-audit-event`;
    //! these cover the wrapper-level decision (`{event, hash}` → verdict).
    use super::*;

    fn ev() -> AuditEvent {
        AuditEvent {
            workflow_id: "wf".into(),
            execution_id: "ex".into(),
            sequence_num: 1,
            timestamp: 1,
            actor: "a".into(),
            action: "act".into(),
            payload: "p".into(),
            previous_hash: "g".into(),
            hmac_signature: None,
        }
    }

    #[test]
    fn accepts_valid_unsigned_when_no_keys() {
        let e = ev();
        let h = e.calculate_hash();
        let v = serde_json::to_value(&e).unwrap();
        assert!(matches!(
            verify_audit_message(&v, Some(&h), &[]),
            VerifyOutcome::Accept { unsigned: false }
        ));
    }

    #[test]
    fn rejects_hash_mismatch_and_missing_hash() {
        let v = serde_json::to_value(ev()).unwrap();
        assert!(matches!(
            verify_audit_message(&v, Some("deadbeef"), &[]),
            VerifyOutcome::Reject("hash_mismatch")
        ));
        assert!(matches!(
            verify_audit_message(&v, None, &[]),
            VerifyOutcome::Reject("hash_mismatch")
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut e = ev();
        e.hmac_signature = Some("deadbeef".into()); // valid hex, wrong MAC
        let h = e.calculate_hash();
        let v = serde_json::to_value(&e).unwrap();
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        assert!(matches!(
            verify_audit_message(&v, Some(&h), &[key]),
            VerifyOutcome::Reject("bad_signature")
        ));
    }

    #[test]
    fn flags_unsigned_when_keys_present_but_still_accepts() {
        let e = ev();
        let h = e.calculate_hash();
        let v = serde_json::to_value(&e).unwrap();
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        assert!(matches!(
            verify_audit_message(&v, Some(&h), &[key]),
            VerifyOutcome::Accept { unsigned: true }
        ));
    }

    #[test]
    fn rejects_non_audit_event_json() {
        let v = serde_json::json!({"not": "an event"});
        assert!(matches!(
            verify_audit_message(&v, Some("x"), &[]),
            VerifyOutcome::Reject("event_deserialize_failed")
        ));
    }
}

/// D3 pin for `talos_audit_verification_failures_total`.
///
/// Both stages are driven through the REAL production functions the ingest
/// loop and the sweep call (`verify_audit_message`,
/// `record_chain_verification_outcome`), and the counter is read back — NOT a
/// `render_prometheus` shape test, which is the exact thing that let dead
/// metrics look alive until #620.
///
/// Also pins the label VALUES the alert selects on. An alert filtering
/// `stage="events"` or `stage="chains"` against code that emits `event` /
/// `chain` is the `provider="both"` defect repeated: a live counter, an alert
/// that can never fire.
#[cfg(test)]
mod audit_verification_metric_tests {
    use super::*;

    /// `set_global` is a process-wide one-shot `OnceLock` shared with sibling
    /// tests in this binary, so assert DELTAS read back through
    /// `talos_metrics::global()`, never absolutes.
    fn stage_count(stage: &str) -> f64 {
        talos_metrics::global()
            .expect("global installed")
            .audit_verification_failures_total
            .with_label_values(&[stage])
            .get()
    }

    fn ev() -> AuditEvent {
        AuditEvent {
            workflow_id: "wf".into(),
            execution_id: "ex".into(),
            sequence_num: 1,
            timestamp: 1,
            actor: "a".into(),
            action: "act".into(),
            payload: "p".into(),
            previous_hash: "g".into(),
            hmac_signature: None,
        }
    }

    fn report(ok: bool) -> ChainVerificationReport {
        ChainVerificationReport {
            execution_id: "ex".into(),
            workflow_id: "wf".into(),
            total_events: 3,
            ok,
            signatures_checked: true,
            breaks: Vec::new(),
        }
    }

    #[test]
    fn event_stage_counts_on_the_real_ingest_verification_path() {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));

        // A rejected message — the ingest loop quarantines this and never
        // persists it. Nothing but a log recorded it before this counter.
        let v = serde_json::to_value(ev()).expect("serialize");
        let before = stage_count(AUDIT_STAGE_EVENT);
        assert!(matches!(
            verify_audit_message(&v, Some("deadbeef"), &[]),
            VerifyOutcome::Reject("hash_mismatch")
        ));
        assert_eq!(
            stage_count(AUDIT_STAGE_EVENT) - before,
            1.0,
            "a rejected audit event must reach stage=\"event\""
        );

        // An ACCEPTED message must not move it — a counter that also counts
        // the healthy path turns a `> 0` critical alert into a pager loop.
        let good = ev();
        let h = good.calculate_hash();
        let gv = serde_json::to_value(&good).expect("serialize");
        let before = stage_count(AUDIT_STAGE_EVENT);
        assert!(matches!(
            verify_audit_message(&gv, Some(&h), &[]),
            VerifyOutcome::Accept { .. }
        ));
        assert_eq!(stage_count(AUDIT_STAGE_EVENT) - before, 0.0);
    }

    #[test]
    fn chain_stage_counts_only_broken_chains_not_unreadable_ones() {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();

        // ok chain → no count.
        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(report(true)), Uuid::nil(), Uuid::nil());
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - before, 0.0);
        assert_eq!(stats.verified_ok, 1);

        // broken chain → exactly one count.
        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(report(false)), Uuid::nil(), Uuid::nil());
        assert_eq!(
            stage_count(AUDIT_STAGE_CHAIN) - before,
            1.0,
            "a chain WITH breaks must reach stage=\"chain\""
        );
        assert_eq!(stats.failed, 1);

        // S3/IO error → `errored`, NOT a verification failure. Counting it
        // would make an object-store blip page as a compliance incident.
        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(
            &mut stats,
            Err(anyhow::anyhow!("s3 unreachable")),
            Uuid::nil(),
            Uuid::nil(),
        );
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - before, 0.0);
        assert_eq!(stats.errored, 1);
    }

    /// The two stage labels are exactly what
    /// `deploy/helm/talos/files/alerts.yaml` selects on.
    #[test]
    fn stage_label_values_are_the_ones_the_alerts_select() {
        assert_eq!(AUDIT_STAGE_EVENT, "event");
        assert_eq!(AUDIT_STAGE_CHAIN, "chain");
    }
}

#[cfg(test)]
mod sweep_coverage_pins {
    //! A sweep that did not finish its window must not be reportable as clean.
    //!
    //! These pin the two halves separately: the FLAG (`cap_hit`, here) and the
    //! LOG BRANCH that consumes it (`controller/src/bootstrap/background.rs`).
    //! Pinning only the flag would leave the original defect — a truncated
    //! sweep logging "completed clean" — perfectly reachable with the flag set
    //! and ignored.
    use super::ChainSweepStats;

    /// Mirrors the assignment in `run_chain_verification_sweep`, which needs
    /// Postgres and an S3/WORM endpoint to drive end-to-end.
    fn cap_hit(rows: usize, max_executions: i64) -> bool {
        max_executions > 0 && rows as i64 >= max_executions
    }

    #[test]
    fn a_full_page_marks_the_sweep_incomplete() {
        assert!(
            cap_hit(500, 500),
            "a window that filled the cap left older rows unverified"
        );
        assert!(cap_hit(501, 500));
    }

    #[test]
    fn a_short_page_is_a_finished_window() {
        // The reference deployment: max 77 terminal executions per rolling 2h
        // window against a cap of 500, so this is the live case today.
        assert!(!cap_hit(77, 500));
        assert!(!cap_hit(0, 500));
    }

    #[test]
    fn no_findings_does_not_by_itself_mean_clean() {
        // The heart of it. `failed == 0 && errored == 0` is trivially satisfied
        // by rows nobody read, so the clean-bill branch must ALSO require
        // !cap_hit. If someone drops that condition this states why not.
        let truncated_but_no_findings = ChainSweepStats {
            scanned: 500,
            verified_ok: 500,
            failed: 0,
            errored: 0,
            cap_hit: true,
        };
        assert!(
            truncated_but_no_findings.failed == 0 && truncated_but_no_findings.errored == 0,
            "the pre-fix clean-bill predicate is satisfied here"
        );
        assert!(
            truncated_but_no_findings.cap_hit,
            "...and yet the window was not finished, which is why the predicate is insufficient"
        );
    }

    /// The consumer half: the controller must branch on `cap_hit` BEFORE the
    /// clean-bill branch, and must not describe a capped sweep as clean.
    #[test]
    fn the_controller_cannot_certify_a_truncated_sweep() {
        let src = include_str!("../../controller/src/bootstrap/background.rs");
        let clean = concat!("audit chain verification sweep ", "completed clean");
        let guard = concat!("} else if stats.", "cap_hit {");
        let (guard_at, clean_at) = (
            src.find(guard)
                .expect("the cap_hit branch is gone; a truncated sweep can be certified clean"),
            src.find(clean).expect("the clean-bill log line moved"),
        );
        assert!(
            guard_at < clean_at,
            "the cap_hit branch must precede the clean-bill branch, or a truncated sweep still \
             reports clean"
        );
    }
}
