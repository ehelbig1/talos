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
    audit_verify_keys, verify_chain, AttemptChainReport, AuditEvent, ChainBreak,
    ChainVerificationReport,
};

pub mod batch_dedupe;
pub mod population;
pub mod verifier;
use population::{roll_up_by_workflow_execution, JobChainOutcome};
pub use population::{
    LedgerTarget, WorkflowExecutionRollup, LEDGER_GENESIS_WORKFLOW_COLUMN, LEDGER_KEY_SPACE,
};
use uuid::Uuid;
pub use verifier::{
    build_audit_verifier_client_from_env, build_verifier_client, last_chain_sweep,
    ChainSweepSnapshot, ChainVerifyError, ChainVerifyErrorKind, VerifierClient,
    VerifierCredentials,
};
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

/// Count one EXACT duplicate dropped at the writer.
///
/// Deliberately NOT `talos_audit_verification_failures_total`: that series'
/// HELP text says "positive tamper/corruption evidence" and a CRITICAL alert
/// fires on it. A redelivery is the transport working as designed, so it gets
/// its own series and no alert. Same reasoning that keeps
/// `audit_chain_unverifiable_total` off the tamper counter.
fn inc_batch_duplicate_delivery() {
    if let Some(m) = talos_metrics::global() {
        m.audit_ledger_duplicate_deliveries_total
            .with_label_values(&[AUDIT_DUPLICATE_SCOPE_BATCH])
            .inc();
    }
}

/// The only `scope` label value with a live increment site. A second value
/// must arrive with its own writer AND its own pre-seed, or check 58's
/// dead-metric rule is being satisfied by a label nothing ever touches.
pub(crate) const AUDIT_DUPLICATE_SCOPE_BATCH: &str = "batch";

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
/// `None` when no endpoint is configured.
///
/// **This is the WRITE path ONLY, and the sentence this replaces was the whole
/// bug.** It used to read "Shared by the subscriber (write path) and
/// `verify_execution_chain` (read path) so the (endpoint, path-style)
/// resolution can never drift" — true about the endpoint, and fatal about the
/// CREDENTIALS, which `aws_config::load_defaults` takes from the `AWS_*`
/// chain. On every deployment of this platform those are the
/// `audit_write_only` identity (`s3:PutObject` and nothing else), so the read
/// path got AccessDenied on every listing and chain verification never once
/// succeeded. The read path is now
/// [`verifier::build_audit_verifier_client_from_env`], which shares the
/// ENDPOINT resolution ([`verifier::audit_s3_endpoint_from_env`]) — the part
/// that genuinely must not drift — and takes its credentials from the separate
/// read-only verifier identity with no `load_defaults` on its path at all.
pub async fn build_audit_s3_client() -> Option<S3Client> {
    // ONE endpoint resolution, shared with the verifier: writer and verifier
    // must address the SAME bucket, or the verifier reads a different store
    // and reports a clean chain about objects nobody wrote.
    let s3_endpoint = verifier::audit_s3_endpoint_from_env()?;
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
) -> std::result::Result<ChainVerificationReport, ChainVerifyError> {
    let client = match build_audit_verifier_client_from_env() {
        VerifierClient::Ready(c) => c,
        VerifierClient::NoEndpoint => {
            return Err(ChainVerifyError::new(
                ChainVerifyErrorKind::Other,
                "no audit S3 endpoint configured",
                "set AWS_ENDPOINT_URL or MINIO_ENDPOINT — the WORM chain has no durable store \
                 to verify"
                    .to_string(),
            ))
        }
        VerifierClient::NoCredentials => {
            return Err(ChainVerifyError::new(
                ChainVerifyErrorKind::NoCredentials,
                "no audit-chain verifier identity configured",
                format!(
                    "set {} and {}",
                    verifier::VERIFIER_ACCESS_KEY_ENV,
                    verifier::VERIFIER_SECRET_KEY_ENV
                ),
            ))
        }
    };
    let bucket = audit_bucket_name();
    verify_execution_chain(&client, &bucket, workflow_id, execution_id).await
}

/// Seconds an execution must be terminal before its chain may be verified.
///
/// The audit consumer batches to the object store every few seconds, so a
/// just-finished execution's chain is legitimately incomplete and would report
/// a false sequence gap. ONE home: the background sweep and the
/// `security_audit` probe must select from the SAME population, or the check
/// grades a set the standing control never looks at.
pub const CHAIN_SETTLE_SECS: i64 = 120;

/// The most recent chain the verifier is entitled to verify.
///
/// Enumerates `module_executions`, because that is the id space the WRITER
/// keys — see [`population`] for the binding and the measurement. Same
/// eligibility predicate as [`run_chain_verification_sweep`] — terminal,
/// `completed_at` outside the settle window, unique `ORDER BY` tiebreaker —
/// deliberately, because this is what `security_audit`'s round-trip check
/// verifies and a check that graded a different population would say nothing
/// about the standing sweep. Returns `Ok(None)` when nothing is eligible,
/// which is a QUIET deployment and not a finding; the `Err` is the third value
/// and must never be folded into it.
///
/// `workflow_execution_id IS NOT NULL` is a REQUIREMENT, not a filter of
/// convenience: `verify_chain` re-derives genesis from both halves, so a row
/// without one has no chain to name. Measured 2026-09-06: 0 of 48,577
/// `module_executions` rows carry a NULL there, so this excludes nothing
/// today — latent, and stated as such.
///
/// Renamed from `latest_verifiable_execution` in the same change that moved
/// the population: the old name and its `(Uuid, Uuid)` return said nothing
/// about WHICH ids, and a caller that kept compiling against the old shape
/// would have gone on grading the wrong id space silently.
pub async fn latest_verifiable_ledger_target(
    db_pool: &PgPool,
    settle_secs: i64,
) -> Result<Option<LedgerTarget>> {
    let row = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, workflow_execution_id \
         FROM module_executions \
         WHERE status IN ('completed', 'failed', 'cancelled') \
           AND completed_at IS NOT NULL \
           AND completed_at <= NOW() - (INTERVAL '1 second' * $1) \
           AND workflow_execution_id IS NOT NULL \
         ORDER BY completed_at DESC, id DESC \
         LIMIT 1",
    )
    .bind(settle_secs)
    .fetch_optional(db_pool)
    .await?;
    Ok(row.map(
        |(module_execution_id, workflow_execution_id)| LedgerTarget {
            module_execution_id,
            workflow_execution_id,
        },
    ))
}

/// Every verifiable chain under ONE workflow execution.
///
/// The on-demand operator path takes a workflow-execution id (that is what
/// `list_executions` hands them), and the ledger has no chain at that grain —
/// it has one per module dispatch. So the id is resolved to its jobs here and
/// each job's chain is verified separately, rather than the caller's id being
/// used as a prefix the writer has never written.
///
/// Deliberately CROSS-TENANT (no `user_id` predicate): the only caller is the
/// platform-admin GraphQL field, whose authorization is established upstream
/// by `is_platform_admin` — the same rationale
/// `ExecutionRepository::get_workflow_id_any_user` carries, one call above it.
/// Do NOT reuse this from a tenant-facing surface.
///
/// `Ok(vec![])` means the workflow execution ran no modules — a real answer,
/// and the reason the aggregate must NOT report `ok` from an empty job set.
pub async fn ledger_targets_for_workflow_execution(
    db_pool: &PgPool,
    workflow_execution_id: Uuid,
) -> Result<Vec<LedgerTarget>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM module_executions \
         WHERE workflow_execution_id = $1 \
         ORDER BY started_at ASC, id ASC",
    )
    .bind(workflow_execution_id)
    .fetch_all(db_pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(module_execution_id,)| LedgerTarget {
            module_execution_id,
            workflow_execution_id,
        })
        .collect())
}

/// Tally from one [`run_chain_verification_sweep`] pass.
///
/// The unqualified counters are PER JOB (per `module_executions` row), because
/// that is the grain the ledger is keyed at — see [`population`]. `rollup`
/// lifts them to the grain an operator asks at. The two are reported side by
/// side and never merged: "37 of 40 jobs verified" and "8 of 9 workflow
/// executions verified" are both true and answer different questions.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChainSweepStats {
    /// Jobs (module executions) queried — terminal, within the window, capped.
    pub scanned: usize,
    /// Chains that verified with no breaks AND held at least one event.
    ///
    /// The event floor is load-bearing: `verify_chain` over an EMPTY set
    /// returns `ok == true` (there are no gaps in nothing), so counting an
    /// empty prefix here would be a "verified nothing" claim. See
    /// [`ChainSweepStats::empty`].
    pub verified_ok: usize,
    /// Prefixes that READ CLEANLY and held ZERO events.
    ///
    /// Split out 2026-09-06, and the measurement is why: `verify_chain` over
    /// an empty event set returns `ok == true`, so before this field existed
    /// an empty read was indistinguishable from a verified chain. At the time
    /// it was the WHOLE population — the sweep enumerated
    /// `workflow_executions` while every ledger prefix is a
    /// `module_executions` id, so 34 of 34 executions in its own 2 h window
    /// read empty. The population is now the one the writer keys, and the
    /// same measurement says an empty prefix should be RARE there: 200 of 200
    /// recent module executions had a non-empty prefix. So a non-zero `empty`
    /// is now a real per-execution finding rather than the expected reading,
    /// and it is still not folded into `verified_ok`.
    pub empty: usize,
    /// Chains WITH breaks — tamper / corruption / gap / linkage / bad HMAC.
    ///
    /// A byte-identical REDELIVERY is not one of these. It is counted in
    /// [`ChainSweepStats::duplicate_delivery`] and, when it is the only
    /// finding, in `verified_ok` — see
    /// [`talos_audit_event::ChainBreak::is_tamper_evidence`].
    pub failed: usize,
    /// Chains carrying at least one BYTE-IDENTICAL redelivery
    /// ([`talos_audit_event::ChainBreak::DuplicateDelivery`]).
    ///
    /// Reported beside `verified_ok`, never folded into `failed`: one event
    /// that reached the ledger twice altered, added and removed nothing, so
    /// calling it tamper evidence is a false positive on the one control that
    /// exists to raise a true one. Counted independently of the arm the job
    /// landed in, so a chain with a REAL break AND a redelivery shows up in
    /// both numbers rather than having the redelivery hidden by the break.
    pub duplicate_delivery: usize,
    /// Chains holding MORE THAN ONE controller dispatch attempt.
    ///
    /// A re-dispatch re-uses the `job_id`, and the worker that picks it up is
    /// credential-free — it cannot read the prior dispatch's ledger, so it
    /// opens a fresh chain at `sequence_num` 1 under the same prefix. Before
    /// the attempt reached the wire that shape was reported as
    /// `DuplicateSequence`, i.e. CRITICAL tamper evidence, for a job that had
    /// merely been retried. Now it is a partition, and this is the number that
    /// says how often it happens.
    ///
    /// Reported BESIDE the verdict, never inside it: such a chain verifies and
    /// lands in `verified_ok`. Counted independently of the arm the job landed
    /// in, so a chain with a REAL break AND two attempts shows up in both
    /// numbers — the same rule `duplicate_delivery` follows.
    pub multi_attempt: usize,
    /// Executions whose chain could not be read (S3/IO error) — unverified.
    pub errored: usize,
    /// The row cap bound: there were AT LEAST `scanned` executions in the
    /// window and the oldest of them were not verified.
    ///
    /// # Why this is not merely a disclosure
    ///
    /// The sweep takes `ORDER BY completed_at DESC ... LIMIT max_jobs`
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
    /// breaks a chain and then generates more than `max_jobs` completions
    /// inside one window would earn a permanent, unqualified "clean" for that
    /// break.
    ///
    /// This flag does not fix the coverage gap — closing that needs a cursor, or
    /// a lookback the operator has sized against their completion rate. It stops
    /// the gap being reported as a clean bill of health, which is the difference
    /// between an unverified window and a window falsely certified.
    pub cap_hit: bool,
    /// Set when the sweep STOPPED EARLY on a deployment-wide condition
    /// (`AccessDenied`, `NoSuchBucket`, or no verifier identity at all).
    ///
    /// # Why abort rather than log once per job
    ///
    /// The sweep drives up to `max_jobs` verifications through ONE client
    /// against ONE bucket. When the first answer is "this identity may not
    /// read this bucket", the rest cannot differ — they are identical WARNs
    /// whose only effect is to bury a per-job finding, plus that many needless
    /// round trips. Measured on the dev stack 2026-09-06: 37 executions, 37
    /// identical `service error` WARNs, one cause. `NotFound` and `Transport`
    /// are deliberately NOT abort-worthy — a missing prefix is a fact about
    /// that job and a reset connection may be the last one.
    ///
    /// The flag is a CLAIM ABOUT COVERAGE, in the same family as `cap_hit`:
    /// `failed == 0 && errored == 1` after an abort must never read as a clean
    /// window, because everything after the first was not looked at.
    pub aborted: Option<ChainVerifyErrorKind>,
    /// Jobs in the window whose `workflow_execution_id` is NULL, so no genesis
    /// pair could be formed and NOTHING was attempted for them.
    ///
    /// Reported rather than filtered away, because "we did not look" must not
    /// arrive as part of a clean count — the class this whole change is about.
    /// Measured 2026-09-06: 0 of 48,577 rows platform-wide carry a NULL there,
    /// so this is LATENT today and is stated as such rather than dressed up.
    pub unbound: usize,
    /// The per-job tally lifted to workflow executions, worst outcome wins.
    ///
    /// Present because every OTHER surface on this platform is keyed on
    /// `workflow_executions.id`, and a report whose only number is per-job
    /// cannot be joined to any of them. Verified at the grain the WRITER keys;
    /// reported at the grain the OPERATOR asks.
    pub rollup: WorkflowExecutionRollup,
}

/// Periodic sweep that runs the offline chain verifier over recently-completed
/// executions and emits a loud structured event for any break (finding #2).
/// This is what makes the WORM ledger **continuously** verified rather than
/// only on demand — it runs as a trusted controller-side system task, so it
/// needs no per-tenant scoping and no MCP/RBAC surface.
///
/// Scope: terminal JOBS — `module_executions` rows, because that is the id
/// space the ledger writer keys (see [`population`]) — whose `completed_at`
/// falls in `[now - lookback, now - settle]`, newest first, capped at
/// `max_jobs`. The `settle` floor avoids false "sequence gap" reports on jobs
/// whose audit events are still being batched to S3 (the consumer flushes
/// every few seconds) — only chains old enough to be fully flushed are
/// checked. Run the sweep on an interval that overlaps the lookback window
/// slightly so nothing at a boundary is missed; re-verification is idempotent
/// and cheap.
///
/// ONE query, no join and no N+1: `module_executions` carries BOTH halves of
/// the genesis binding (`id` and `workflow_execution_id`), so the join a
/// reader would expect to `workflow_executions` is not merely batched away —
/// it is unnecessary. Rows with a NULL `workflow_execution_id` come back too
/// and are counted under [`ChainSweepStats::unbound`] rather than filtered out
/// of sight.
pub async fn run_chain_verification_sweep(
    db_pool: &PgPool,
    s3_client: &S3Client,
    bucket: &str,
    lookback_secs: i64,
    settle_secs: i64,
    max_jobs: i64,
) -> ChainSweepStats {
    let mut stats = ChainSweepStats::default();

    let rows = match enumerate_sweep_jobs(db_pool, lookback_secs, settle_secs, max_jobs).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                target: "talos_audit",
                event_kind = "audit_chain_sweep_query_failed",
                error = %e,
                "audit chain sweep could not enumerate module executions — skipping this pass"
            );
            return stats;
        }
    };

    stats.scanned = rows.len();
    // `>=` for the safe direction: a window holding exactly the cap is
    // indistinguishable from one holding more, and the alternative is a sweep
    // that quietly certifies a short window.
    stats.cap_hit = max_jobs > 0 && rows.len() as i64 >= max_jobs;
    // The partition hands back the unbound COUNT alongside the targets, so a
    // row with no genesis pair cannot be obtained-and-forgotten: see
    // `partition_sweep_rows` for the mutation that made this an extracted
    // function rather than an `if let` in this loop.
    let (targets, unbound) = population::partition_sweep_rows(&rows);
    stats.unbound = unbound;
    let mut outcomes: Vec<(Uuid, JobChainOutcome)> = Vec::with_capacity(targets.len());
    for target in targets {
        let outcome = verify_execution_chain(
            s3_client,
            bucket,
            &target.genesis_workflow_id(),
            &target.execution_id(),
        )
        .await;
        let (control, class) = record_chain_verification_outcome(&mut stats, outcome, &target);
        outcomes.push((target.workflow_execution_id, class));
        if control == SweepControl::Abort {
            break;
        }
    }
    stats.rollup = roll_up_by_workflow_execution(&outcomes);
    stats
}

/// The sweep's enumeration query, extracted so a DB test can drive the EXACT
/// statement the sweep issues rather than a paraphrase of it.
///
/// That is not a stylistic preference — it is `updated_at_maintenance_tests`'
/// recorded lesson: a hand-written statement in a test can be green over the
/// shape the writer actually issues. The whole defect this function exists to
/// close was a SELECT naming the wrong table, which no amount of testing the
/// verification logic could have seen.
///
/// `Option<Uuid>` on the second column is deliberate: `workflow_execution_id`
/// is NULLABLE, and a row without one has no genesis pair. It comes back so
/// the caller can COUNT it (`ChainSweepStats::unbound`) instead of filtering
/// it out of sight.
///
/// `INTERVAL '1 second' * $N` (not `make_interval`) — the int4-only
/// `make_interval` args don't apply, and this form takes a bigint bind. Unique
/// `ORDER BY` tiebreaker (`id`) per the pagination-stability rule (check 28).
pub async fn enumerate_sweep_jobs(
    db_pool: &PgPool,
    lookback_secs: i64,
    settle_secs: i64,
    max_jobs: i64,
) -> Result<Vec<(Uuid, Option<Uuid>)>> {
    let rows = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "SELECT id, workflow_execution_id \
         FROM module_executions \
         WHERE status IN ('completed', 'failed', 'cancelled') \
           AND completed_at IS NOT NULL \
           AND completed_at <= NOW() - (INTERVAL '1 second' * $1) \
           AND completed_at >= NOW() - (INTERVAL '1 second' * $2) \
         ORDER BY completed_at DESC, id DESC \
         LIMIT $3",
    )
    .bind(settle_secs)
    .bind(lookback_secs)
    .bind(max_jobs)
    .fetch_all(db_pool)
    .await?;
    Ok(rows)
}

/// Whether the sweep should keep going after one execution's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepControl {
    Continue,
    Abort,
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
    outcome: std::result::Result<ChainVerificationReport, ChainVerifyError>,
    target: &LedgerTarget,
) -> (SweepControl, JobChainOutcome) {
    // Named for what they ARE, not for the ledger field they feed: the log
    // reads `module_execution_id` / `workflow_execution_id`, so an operator
    // grepping either one finds this line, and nobody has to know that the
    // ledger calls the second half `workflow_id`.
    let exec_id = target.module_execution_id;
    let wf_id = target.workflow_execution_id;
    let mut class = JobChainOutcome::VerifiedOk;
    // Counted BEFORE the arms, and independently of them: a redelivery is a
    // property of the chain, not of the verdict, so a job that also has a real
    // break must still report the redelivery rather than have it swallowed by
    // the louder finding.
    if let Ok(report) = &outcome {
        // Counted BEFORE the arms and independently of them, for the same
        // reason as the redelivery count below it: how many dispatches a job
        // took is a property of the chain, not of the verdict.
        let attempts = report.dispatch_attempt_count();
        if attempts > 1 {
            stats.multi_attempt += 1;
            inc_chain_multi_attempt();
            tracing::info!(
                target: "talos_audit",
                event_kind = "audit_chain_multi_attempt",
                module_execution_id = %target.module_execution_id,
                workflow_execution_id = %target.workflow_execution_id,
                ledger_key_space = LEDGER_KEY_SPACE,
                dispatch_attempts = attempts,
                "a job's audit prefix holds one chain PER CONTROLLER DISPATCH ATTEMPT — \
                 the controller re-dispatched this job_id and the credential-free \
                 worker could not know it, so each dispatch opened a fresh chain at \
                 sequence 1 against the same genesis. Each is verified as its own \
                 chain. This is a RETRY, not tamper evidence."
            );
        }
        let duplicates = report
            .breaks
            .iter()
            .filter(|b| matches!(b, ChainBreak::DuplicateDelivery { .. }))
            .count();
        if duplicates > 0 {
            stats.duplicate_delivery += 1;
            inc_chain_duplicate_delivery();
            tracing::info!(
                target: "talos_audit",
                event_kind = "audit_chain_duplicate_delivery",
                module_execution_id = %target.module_execution_id,
                workflow_execution_id = %target.workflow_execution_id,
                ledger_key_space = LEDGER_KEY_SPACE,
                duplicate_events = duplicates,
                "a job's audit chain carries byte-identical redelivered event(s) — \
                 at-least-once delivery, NOT tamper evidence. The chain's continuity is \
                 verified over the deduped sequence; the writer drops same-batch copies \
                 and cannot see cross-batch ones (its store identity is write-only)."
            );
        }
    }
    let control = match outcome {
        // An EMPTY prefix is not a verified chain. It does not stamp the
        // last-verified-ok gauge either — "the control works" must not be
        // claimed from a read that returned nothing.
        Ok(report) if report.ok && report.total_events == 0 => {
            stats.empty += 1;
            class = JobChainOutcome::Empty;
            inc_chain_unverifiable(ChainVerifyErrorKind::EmptyChain);
            tracing::warn!(
                target: "talos_audit",
                event_kind = "audit_chain_verification_empty",
                module_execution_id = %exec_id,
                workflow_execution_id = %wf_id,
                ledger_key_space = LEDGER_KEY_SPACE,
                reason = ChainVerifyErrorKind::EmptyChain.metric_label(),
                remedy = ChainVerifyError::new(
                    ChainVerifyErrorKind::EmptyChain,
                    "empty prefix",
                    String::new()
                )
                .remedy(),
                "a job's audit prefix held NO events — nothing was verified"
            );
            SweepControl::Continue
        }
        Ok(report) if report.ok => {
            stats.verified_ok += 1;
            set_last_verified_ok_timestamp();
            SweepControl::Continue
        }
        Ok(report) => {
            stats.failed += 1;
            class = JobChainOutcome::Failed;
            inc_audit_verification_failure(AUDIT_STAGE_CHAIN);
            // The security signal — one ERROR per broken chain so SIEM
            // can alert per job. `breaks` is a structured list.
            tracing::error!(
                target: "talos_audit",
                event_kind = "audit_chain_verification_failed",
                module_execution_id = %exec_id,
                workflow_execution_id = %wf_id,
                ledger_key_space = LEDGER_KEY_SPACE,
                total_events = report.total_events,
                signatures_checked = report.signatures_checked,
                breaks = ?report.breaks,
                "audit chain verification FAILED for a completed job — \
                 possible tampering, deletion, reorder, or corruption"
            );
            SweepControl::Continue
        }
        Err(e) => {
            stats.errored += 1;
            class = JobChainOutcome::Errored;
            // The counter the `Err` arm never had. `talos_audit_verification_failures_total`
            // is deliberately NOT touched here — unverifiable is not
            // verified-bad (#578), and folding the two would make an object-store
            // blip page as a compliance incident. This is its own series, its
            // own alert, and its own severity.
            inc_chain_unverifiable(e.kind);
            let abort = e.kind.aborts_sweep();
            tracing::warn!(
                target: "talos_audit",
                event_kind = "audit_chain_verification_errored",
                module_execution_id = %exec_id,
                workflow_execution_id = %wf_id,
                ledger_key_space = LEDGER_KEY_SPACE,
                reason = e.kind.metric_label(),
                context = %e.context,
                // The SDK's FULL error chain. The old `error = %e` rendered
                // "service error" and nothing else.
                error = %e.detail,
                remedy = e.remedy(),
                aborting_sweep = abort,
                "could not verify an execution's audit chain — left unverified"
            );
            if abort {
                stats.aborted = Some(e.kind);
                SweepControl::Abort
            } else {
                SweepControl::Continue
            }
        }
    };
    (control, class)
}

/// Count one job chain found carrying a byte-identical redelivery.
///
/// No alert selects this series, deliberately: see the counter's HELP text.
fn inc_chain_duplicate_delivery() {
    if let Some(m) = talos_metrics::global() {
        m.audit_chain_duplicate_deliveries_total.inc();
    }
}

/// Count one job chain found holding more than one controller dispatch attempt.
///
/// No alert selects this series, deliberately: see the counter's HELP text.
fn inc_chain_multi_attempt() {
    if let Some(m) = talos_metrics::global() {
        m.audit_chain_multi_attempt_jobs_total.inc();
    }
}

/// Count one unverifiable chain, by classified reason.
///
/// Inert when `talos_metrics::set_global` has not run, per the
/// `talos_metrics::global` contract — same shape as
/// [`inc_audit_verification_failure`].
fn inc_chain_unverifiable(kind: ChainVerifyErrorKind) {
    if let Some(m) = talos_metrics::global() {
        m.audit_chain_unverifiable_total
            .with_label_values(&[kind.metric_label()])
            .inc();
    }
}

/// Seconds since the unix epoch, as the float a Prometheus gauge holds.
///
/// The `prometheus` crate exposes no `set_to_current_time` on `Gauge` (unlike
/// the Go client), so the timestamp is taken here — once, from `chrono::Utc`,
/// the same clock the sweep snapshot uses, so the gauge and the snapshot can
/// never disagree about when a pass happened.
fn unix_now_secs_f64() -> f64 {
    chrono::Utc::now().timestamp() as f64
}

/// Stamp "a chain verified clean at this instant".
///
/// A GAUGE of a unix timestamp rather than a counter: the operator question is
/// "when did this control last work?", and `time() - gauge > N` answers it
/// while a counter delta cannot distinguish "never started" from "stopped an
/// hour ago". Left UNSET (and therefore ABSENT) until the first success, which
/// is the honest rendering — a gauge seeded at 0 would read as 1970 and make
/// every staleness alert fire on a healthy cold boot.
fn set_last_verified_ok_timestamp() {
    if let Some(m) = talos_metrics::global() {
        m.audit_chain_last_verified_ok_timestamp_seconds
            .set(unix_now_secs_f64());
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
    max_jobs: i64,
) -> Option<ChainSweepStats> {
    let client = match build_audit_verifier_client_from_env() {
        VerifierClient::Ready(c) => c,
        VerifierClient::NoEndpoint => {
            tracing::debug!(
                target: "talos_audit",
                "audit chain verification sweep skipped — no S3 endpoint configured"
            );
            return None;
        }
        // An endpoint IS configured, so a WORM ledger is being written and
        // nothing is verifying it. That is a broken control, not an absent
        // one, and it gets an ERROR, a counter and a published snapshot so
        // `security_audit` can report it — never a silent fall back to the
        // writer's `AWS_*`, which cannot read the bucket by design.
        VerifierClient::NoCredentials => {
            inc_chain_unverifiable(ChainVerifyErrorKind::NoCredentials);
            let stats = ChainSweepStats {
                aborted: Some(ChainVerifyErrorKind::NoCredentials),
                ..ChainSweepStats::default()
            };
            publish_sweep_snapshot(&stats);
            tracing::error!(
                target: "talos_audit",
                event_kind = "audit_chain_verifier_identity_missing",
                reason = ChainVerifyErrorKind::NoCredentials.metric_label(),
                access_key_env = verifier::VERIFIER_ACCESS_KEY_ENV,
                secret_key_env = verifier::VERIFIER_SECRET_KEY_ENV,
                "the WORM audit ledger is being WRITTEN and nothing can verify it — no \
                 read-only audit-chain verifier identity is configured. The writer's \
                 credentials are write-only by design and are deliberately NOT used here."
            );
            return Some(stats);
        }
    };
    let bucket = audit_bucket_name();
    let stats = run_chain_verification_sweep(
        db_pool,
        &client,
        &bucket,
        lookback_secs,
        settle_secs,
        max_jobs,
    )
    .await;
    publish_sweep_snapshot(&stats);
    Some(stats)
}

/// Publish the pass's outcome for `security_audit`, and stamp the
/// sweep-ran-at gauge.
///
/// The gauge answers "is the sweep running at all?" independently of whether
/// it verified anything — the two questions have different answers on exactly
/// the deployment this change is about (a sweep that runs hourly and verifies
/// nothing), and one series cannot express both.
fn publish_sweep_snapshot(stats: &ChainSweepStats) {
    let now = chrono::Utc::now().timestamp();
    verifier::publish_chain_sweep_snapshot(ChainSweepSnapshot {
        scanned: stats.scanned,
        verified_ok: stats.verified_ok,
        empty: stats.empty,
        failed: stats.failed,
        duplicate_delivery: stats.duplicate_delivery,
        multi_attempt: stats.multi_attempt,
        errored: stats.errored,
        unbound: stats.unbound,
        cap_hit: stats.cap_hit,
        aborted: stats.aborted,
        rollup: stats.rollup,
        finished_at_unix: now,
    });
    if let Some(m) = talos_metrics::global() {
        m.audit_chain_sweep_timestamp_seconds
            .set(unix_now_secs_f64());
    }
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

    // Phase 1b: drop EXACT duplicates inside this batch.
    //
    // An audit event can reach this subscriber more than once — at-least-once
    // is the transport's contract, and (measured 2026-09-07) the worker's own
    // retry loop appended one terminal anchor per attempt from a fresh
    // `ExecutionLedger`, so two attempts inside one wall-clock second produced
    // two BYTE-IDENTICAL events. Written through, they became one `.jsonl`
    // object with two identical lines, which the offline verifier reported as
    // `DuplicateSequence` under "possible tampering, deletion, reorder, or
    // corruption" — a false CRITICAL on the one control that exists to raise a
    // true one.
    //
    // Only EXACT duplicates are dropped: a conflicting pair (one sequence, two
    // contents) is a substitution and MUST reach the ledger and the verifier
    // intact. See `batch_dedupe` for the identity, and for why the writer
    // cannot close the cross-BATCH case (its S3 identity is write-only by
    // design — do not widen it; the verifier classifies that case instead).
    //
    // Placed BEFORE the user_id resolve and the OTLP span emission so a
    // dropped copy costs no query and emits no duplicate span either.
    let (keep_indices, dropped_duplicates) =
        batch_dedupe::partition_batch_duplicates(parsed.iter().map(|p| {
            let event = p.wrapper.get("event");
            (
                p.idx,
                batch_dedupe::BatchEventKey {
                    execution_id: p.execution_id.clone(),
                    sequence_num: event
                        .and_then(|e| e.get("sequence_num"))
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                    hash: p
                        .wrapper
                        .get("hash")
                        .and_then(|h| h.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    hmac_signature: event
                        .and_then(|e| e.get("hmac_signature"))
                        .and_then(|h| h.as_str())
                        .map(str::to_string),
                },
                event
                    .and_then(|e| e.get("action"))
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            )
        }));
    let duplicate_indices: Vec<usize> = dropped_duplicates.iter().map(|d| d.idx).collect();
    if !dropped_duplicates.is_empty() {
        for _ in &dropped_duplicates {
            inc_batch_duplicate_delivery();
        }
        // ONE line per batch, at INFO. This is the transport working as
        // designed, not an incident: an ERROR here would be the same
        // train-the-operator-to-ignore-it defect the classification fixes.
        let kinds: HashSet<&str> = dropped_duplicates
            .iter()
            .map(|d| d.event_kind.as_str())
            .collect();
        let mut kinds: Vec<&str> = kinds.into_iter().collect();
        kinds.sort_unstable();
        tracing::info!(
            target: "talos_audit",
            event_kind = "audit_batch_duplicate_delivery",
            dropped = dropped_duplicates.len(),
            event_kinds = ?kinds,
            executions = dropped_duplicates
                .iter()
                .map(|d| d.execution_id.as_str())
                .collect::<HashSet<&str>>()
                .len(),
            "dropped {} byte-identical audit event copy(ies) from this batch — \
              at-least-once delivery, NOT tamper evidence; the surviving copy is \
              written and every copy is acknowledged",
            dropped_duplicates.len()
        );
        let keep: HashSet<usize> = keep_indices.into_iter().collect();
        parsed.retain(|p| keep.contains(&p.idx));
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
    // A dropped duplicate is TERMINAL: its content is already being written
    // by the copy that survived, so it must be ACKed. Leaving it unacked
    // would have JetStream redeliver it after `ack_wait` forever.
    all_to_ack.extend(duplicate_indices);
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
) -> std::result::Result<ChainVerificationReport, ChainVerifyError> {
    let prefix = format!("{execution_id}/");
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut continuation: Option<String> = None;
    let mut object_count = 0usize;

    loop {
        let mut req = s3_client.list_objects_v2().bucket(bucket).prefix(&prefix);
        if let Some(token) = &continuation {
            req = req.continuation_token(token);
        }
        // CLASSIFIED, not stringified. `%e` on an `SdkError` renders the two
        // words "service error" — AccessDenied, NoSuchBucket and a reset
        // connection are indistinguishable in it, and that is exactly what an
        // operator needed to tell apart on this path (37 identical WARNs an
        // hour on the dev stack, 2026-09-06).
        let page = req.send().await.map_err(|e| {
            ChainVerifyError::from_sdk(format!("list_objects_v2 failed for {prefix}"), &e)
        })?;

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
                .map_err(|e| {
                    ChainVerifyError::from_sdk(format!("get_object failed for {key}"), &e)
                })?;
            let bytes = got
                .body
                .collect()
                .await
                .map_err(|e| {
                    // A body that stops mid-stream is a transport fault, not a
                    // service answer — there is no S3 error code to read.
                    ChainVerifyError::new(
                        ChainVerifyErrorKind::Transport,
                        format!("reading body of {key} failed"),
                        e.to_string(),
                    )
                })?
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
            dispatch_attempt: 0,
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

    /// Serialises every test in this module that reads a global counter DELTA.
    ///
    /// Asserting deltas rather than absolutes — the rule the doc below states —
    /// is necessary and NOT sufficient: the registry is process-global and
    /// `cargo test` runs these on parallel threads, so another test crossing
    /// the window between `before` and `after` moves the delta regardless.
    /// That was latent while the module held four such tests and became a
    /// reproducible flake at six (measured 2026-09-07: 12/12 green without the
    /// two added here, 1 failure in 6 runs with them). One lock, taken for the
    /// whole body, is the fix; poison is recovered from so one failing test
    /// does not cascade into the rest.
    fn metric_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `set_global` is a process-wide one-shot `OnceLock` shared with sibling
    /// tests in this binary, so assert DELTAS read back through
    /// `talos_metrics::global()`, never absolutes — and hold
    /// [`metric_guard`] for the whole test, or a parallel sibling crosses the
    /// window and moves the delta anyway.
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
            dispatch_attempt: 0,
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
            attempts: vec![talos_audit_event::AttemptChainReport {
                dispatch_attempt: 0,
                total_events: 3,
                ok,
                breaks: Vec::new(),
            }],
        }
    }

    #[test]
    fn event_stage_counts_on_the_real_ingest_verification_path() {
        let _guard = metric_guard();
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
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();

        // ok chain → no count.
        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(report(true)), &nil_target());
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - before, 0.0);
        assert_eq!(stats.verified_ok, 1);

        // broken chain → exactly one count.
        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(report(false)), &nil_target());
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
            Err(ChainVerifyError::new(
                ChainVerifyErrorKind::Transport,
                "s3 unreachable",
                "connection reset".to_string(),
            )),
            &nil_target(),
        );
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - before, 0.0);
        assert_eq!(stats.errored, 1);
    }

    /// A chain holding TWO controller dispatch attempts is VERIFIED, counted in
    /// `verified_ok`, counted separately in `multi_attempt`, and moves the
    /// pre-seeded `talos_audit_chain_multi_attempt_jobs_total` — never
    /// `talos_audit_verification_failures_total`.
    ///
    /// The counter has ONE increment site and this drives it. Check 58 proves
    /// an `.inc()` site EXISTS; only a test that walks the production
    /// classification proves anything reaches it.
    #[test]
    fn a_re_dispatched_job_verifies_and_is_counted_as_a_retry_not_a_failure() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();

        // Two attempts of one job, built by the REAL producer path so the
        // partitioning under test is the one production writes.
        let mut a0 = talos_audit_event::ExecutionLedger::new_for_attempt("wf", "ex", 0);
        let mut a1 = talos_audit_event::ExecutionLedger::new_for_attempt("wf", "ex", 1);
        let events = vec![
            a0.append("worker", "act", "one"),
            a0.append_terminal_anchor("worker"),
            a1.append("worker", "act", "two"),
            a1.append_terminal_anchor("worker"),
        ];
        let report = verify_chain("wf", "ex", &events, &[]);
        assert!(report.ok, "breaks: {:?}", report.breaks);

        let multi_before = talos_metrics::global()
            .expect("global installed")
            .audit_chain_multi_attempt_jobs_total
            .get();
        let fail_before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(report), &nil_target());

        assert_eq!(stats.verified_ok, 1, "a retried job still verifies");
        assert_eq!(stats.failed, 0, "a retry is not a break");
        assert_eq!(stats.multi_attempt, 1);
        assert_eq!(
            talos_metrics::global()
                .expect("global installed")
                .audit_chain_multi_attempt_jobs_total
                .get()
                - multi_before,
            1.0,
            "the multi-attempt counter must move exactly once"
        );
        assert_eq!(
            stage_count(AUDIT_STAGE_CHAIN) - fail_before,
            0.0,
            "a retry must never touch the tamper counter"
        );
    }

    /// The control: an ORDINARY single-attempt chain moves neither the tally
    /// nor the counter, so a non-zero reading means what it says.
    #[test]
    fn a_single_attempt_chain_moves_neither_the_tally_nor_the_counter() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();
        let before = talos_metrics::global()
            .expect("global installed")
            .audit_chain_multi_attempt_jobs_total
            .get();
        record_chain_verification_outcome(&mut stats, Ok(report(true)), &nil_target());
        assert_eq!(stats.multi_attempt, 0);
        assert_eq!(
            talos_metrics::global()
                .expect("global installed")
                .audit_chain_multi_attempt_jobs_total
                .get()
                - before,
            0.0
        );
    }

    /// The whole point, at the sweep's classification site: a chain whose ONLY
    /// finding is a byte-identical redelivery is VERIFIED. It counts in
    /// `verified_ok`, it counts in the separate `duplicate_delivery` tally, and
    /// it must NOT touch `talos_audit_verification_failures_total{stage="chain"}`
    /// — the CRITICAL series. Measured live 2026-09-07, this exact shape was
    /// 1 of the 102 jobs in the first sweep that ever completed.
    #[test]
    fn a_redelivered_chain_is_verified_not_a_tamper_failure() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();
        let mut r = report(true);
        r.breaks.push(ChainBreak::DuplicateDelivery { seq: 1 });

        let before = stage_count(AUDIT_STAGE_CHAIN);
        let before_dupes = chain_duplicate_count();
        record_chain_verification_outcome(&mut stats, Ok(r), &nil_target());

        assert_eq!(
            stage_count(AUDIT_STAGE_CHAIN) - before,
            0.0,
            "a redelivery must not page as tamper evidence"
        );
        assert_eq!(chain_duplicate_count() - before_dupes, 1.0);
        assert_eq!(stats.duplicate_delivery, 1);
        assert_eq!(stats.verified_ok, 1);
        assert_eq!(stats.failed, 0, "never in failed");
    }

    /// The control: a REAL break that also carries a redelivery is still a
    /// failure, and the redelivery is still reported — one finding must not
    /// swallow the other.
    #[test]
    fn a_broken_chain_that_also_redelivered_reports_both() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();
        let mut r = report(false);
        r.breaks.push(ChainBreak::DuplicateDelivery { seq: 1 });
        r.breaks.push(ChainBreak::SequenceGap {
            expected: 2,
            found: 3,
        });

        let before = stage_count(AUDIT_STAGE_CHAIN);
        record_chain_verification_outcome(&mut stats, Ok(r), &nil_target());
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - before, 1.0);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.duplicate_delivery, 1);
        assert_eq!(stats.verified_ok, 0);
    }

    fn chain_duplicate_count() -> f64 {
        talos_metrics::global()
            .expect("metrics")
            .audit_chain_duplicate_deliveries_total
            .get()
    }

    /// The two stage labels are exactly what
    /// `deploy/helm/talos/files/alerts.yaml` selects on.
    #[test]
    fn stage_label_values_are_the_ones_the_alerts_select() {
        let _guard = metric_guard();
        assert_eq!(AUDIT_STAGE_EVENT, "event");
        assert_eq!(AUDIT_STAGE_CHAIN, "chain");
    }

    /// A target whose halves are both nil: these tests are about the
    /// CLASSIFICATION, not about the ids, and naming them keeps the call sites
    /// from re-deciding which half is which.
    fn nil_target() -> LedgerTarget {
        LedgerTarget {
            module_execution_id: Uuid::nil(),
            workflow_execution_id: Uuid::nil(),
        }
    }

    fn unverifiable_count(reason: &str) -> f64 {
        talos_metrics::global()
            .expect("global installed")
            .audit_chain_unverifiable_total
            .with_label_values(&[reason])
            .get()
    }

    /// The counter the `Err` arm never had.
    ///
    /// Before this, an execution whose chain could not be READ incremented
    /// NOTHING — so a verifier that had never once succeeded was, on every
    /// machine-readable surface, indistinguishable from a ledger verified
    /// clean. The mutation "delete the `inc_chain_unverifiable` call" fails
    /// here; so does "classify everything as Other", because the reason label
    /// is asserted.
    #[test]
    fn an_unreadable_chain_counts_under_its_classified_reason() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();

        let before = unverifiable_count("access_denied");
        let tamper_before = stage_count(AUDIT_STAGE_CHAIN);
        let (control, _class) = record_chain_verification_outcome(
            &mut stats,
            Err(ChainVerifyError::new(
                ChainVerifyErrorKind::AccessDenied,
                "list_objects_v2 failed for ex/",
                "AccessDenied".to_string(),
            )),
            &nil_target(),
        );
        assert_eq!(unverifiable_count("access_denied") - before, 1.0);
        // And it must NOT have touched the tamper counter — unverifiable is
        // not verified-bad (#578), and folding the two would make a
        // misconfigured identity page as a compliance incident.
        assert_eq!(stage_count(AUDIT_STAGE_CHAIN) - tamper_before, 0.0);
        assert_eq!(stats.errored, 1);
        // A deployment-wide condition ABORTS: every remaining job would answer
        // identically through the same client against the same bucket.
        assert_eq!(control, SweepControl::Abort);
        assert_eq!(stats.aborted, Some(ChainVerifyErrorKind::AccessDenied));
    }

    /// A per-object or per-request fault does NOT abort the pass: the next
    /// execution may well verify, and stopping would silently shrink the
    /// window's coverage on a transient blip.
    #[test]
    fn a_transient_fault_does_not_abort_the_sweep() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let mut stats = ChainSweepStats::default();

        let before = unverifiable_count("transport");
        let (control, _class) = record_chain_verification_outcome(
            &mut stats,
            Err(ChainVerifyError::new(
                ChainVerifyErrorKind::Transport,
                "list_objects_v2 failed for ex/",
                "connection reset".to_string(),
            )),
            &nil_target(),
        );
        assert_eq!(unverifiable_count("transport") - before, 1.0);
        assert_eq!(control, SweepControl::Continue);
        assert_eq!(stats.aborted, None);
    }

    /// An EMPTY prefix is NOT a verified chain, does not stamp the
    /// last-verified-ok gauge, and is counted under its own reason.
    ///
    /// This is the reading that would otherwise have shipped: repairing the
    /// verifier identity ALONE turns 37 loud AccessDenied WARNs into 37 silent
    /// `verified_ok`, because `verify_chain` over zero events returns
    /// `ok == true` and the sweep was naming `workflow_executions` ids that
    /// the writer never uses as a prefix (0 of 200, measured 2026-09-06). The
    /// sweep now enumerates `module_executions`, so an empty prefix is a real
    /// per-job finding — but the distinction stays load-bearing whichever id
    /// space is enumerated, which is why it is a variant and not a comment.
    #[test]
    fn an_empty_prefix_is_not_a_verified_chain() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let gauge = || {
            talos_metrics::global()
                .expect("global installed")
                .audit_chain_last_verified_ok_timestamp_seconds
                .get()
        };
        let mut stats = ChainSweepStats::default();
        let before = unverifiable_count("empty_chain");
        let gauge_before = gauge();

        let mut empty = report(true);
        empty.total_events = 0;
        let (control, class) =
            record_chain_verification_outcome(&mut stats, Ok(empty), &nil_target());
        assert_eq!(class, JobChainOutcome::Empty);
        assert_eq!(
            stats.verified_ok, 0,
            "an empty prefix is not a verified chain"
        );
        assert_eq!(stats.empty, 1);
        assert_eq!(unverifiable_count("empty_chain") - before, 1.0);
        assert_eq!(
            gauge(),
            gauge_before,
            "an empty read must not stamp \"the control works\""
        );
        // Per-execution, not deployment-wide: an execution can legitimately
        // emit no audit events.
        assert_eq!(control, SweepControl::Continue);
        assert_eq!(stats.aborted, None);
    }

    /// A clean chain stamps "the control worked at this instant". Without it
    /// the staleness rule has nothing to measure against and can only ever
    /// report the absent case.
    #[test]
    fn a_verified_chain_stamps_the_last_verified_ok_gauge() {
        let _guard = metric_guard();
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        let gauge = || {
            talos_metrics::global()
                .expect("global installed")
                .audit_chain_last_verified_ok_timestamp_seconds
                .get()
        };
        // A FRESH registry exports the gauge at 0 until something sets it —
        // which is exactly why the alert on it carries an `absent()`/zero arm
        // rather than reading 1970 as "last verified". Asserted on a local
        // registry, not the process-global one, because sibling tests in this
        // binary share the global and would race a `== 0` assertion on it.
        assert_eq!(
            talos_metrics::TalosMetrics::new()
                .expect("metrics")
                .audit_chain_last_verified_ok_timestamp_seconds
                .get(),
            0.0
        );
        let mut stats = ChainSweepStats::default();
        record_chain_verification_outcome(&mut stats, Ok(report(true)), &nil_target());
        assert!(
            gauge() > 1_700_000_000.0,
            "a verified chain must stamp the gauge with a real unix time, got {}",
            gauge()
        );
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
    fn cap_hit(rows: usize, max_jobs: i64) -> bool {
        max_jobs > 0 && rows as i64 >= max_jobs
    }

    #[test]
    fn a_full_page_marks_the_sweep_incomplete() {
        assert!(
            cap_hit(2000, 2000),
            "a window that filled the cap left older rows unverified"
        );
        assert!(cap_hit(2001, 2000));
    }

    #[test]
    fn a_short_page_is_a_finished_window() {
        // The reference deployment after the population moved to JOBS:
        // measured 2026-09-06, 101 module executions in the sweep's own 2 h
        // window and a peak of 150 in any 2 h bucket over 7 days, against a
        // cap of 2000 — so this is the live case today, with ~13x headroom.
        assert!(!cap_hit(150, 2000));
        assert!(!cap_hit(0, 2000));
    }

    #[test]
    fn no_findings_does_not_by_itself_mean_clean() {
        // The heart of it. `failed == 0 && errored == 0` is trivially satisfied
        // by rows nobody read, so the clean-bill branch must ALSO require
        // !cap_hit. If someone drops that condition this states why not.
        let truncated_but_no_findings = ChainSweepStats {
            aborted: None,
            empty: 0,
            scanned: 500,
            verified_ok: 500,
            failed: 0,
            duplicate_delivery: 0,
            multi_attempt: 0,
            errored: 0,
            unbound: 0,
            cap_hit: true,
            rollup: crate::WorkflowExecutionRollup::default(),
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
