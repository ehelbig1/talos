use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
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
use talos_audit_event::AuditEvent;
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
fn verify_audit_message(
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

// ── OTLP auth-header encryption (L3, 2026-05-28 review) ────────────────────────
//
// SINGLE SOURCE OF TRUTH for encrypting/decrypting the per-tenant OTLP
// streaming auth headers. The GraphQL write path (`talos-api`
// update_audit_settings) and this crate's read path (`OTLPCache::get_tracer`)
// BOTH call these helpers, so the (algorithm, key-derivation, AAD) triple can
// never drift again.
//
// Pre-L3 the two ends were mismatched: the write path encrypted with a
// SecretsManager DEK envelope while the read path decrypted with the RAW
// `TALOS_MASTER_KEY` as the AES key. The GCM tag check therefore ALWAYS failed
// at read time, and the failure was silently swallowed — encrypted headers were
// persisted but never applied, so authenticated audit-log streaming was
// silently non-functional. (See the now-removed NOTE in update_audit_settings.)
//
// This realignment fixes three things at once:
//   1. Correctness — both ends derive the SAME key identically, so the
//      round-trip works.
//   2. Domain separation — the master key is the KEK (it wraps DEKs); using it
//      DIRECTLY as an AES data key (as the old read path did) reused crypto
//      material across primitives. We instead derive a dedicated AEAD subkey via
//      HKDF-SHA256 with a unique label (same hardening as the secret-envelope
//      and checkpoint subkeys).
//   3. Swap resistance — AAD binds the ciphertext to the owning `user_id`, so a
//      DB-write attacker can't transpose one tenant's header blob into another's
//      `user_audit_settings` row and have it decrypt.
//
// Old ciphertext (SecretsManager-DEK, no AAD) does not decrypt under this scheme
// and fails closed with a logged WARN — acceptable because it never decrypted
// under the broken read path either, so there is no working data to migrate.

/// HKDF-SHA256 domain-separation label for the OTLP auth-header AEAD subkey.
const OTLP_HEADER_AEAD_LABEL: &[u8] = b"talos/master-key/audit-otlp-header-aead/v1";

/// v2 label (finding #1): the OTLP subkey folds the owning `user_id` into
/// the HKDF `info`, so each tenant gets its own derived key. The AES-GCM
/// random-nonce budget is then per-tenant (this surface is low-volume —
/// one row per tenant, written on a settings change — so the uniformity
/// matters more than the volume). Distinct label from v1.
const OTLP_HEADER_AEAD_LABEL_V2: &[u8] = b"talos/master-key/audit-otlp-header-aead/v2-per-user";

/// v1 (legacy) OTLP subkey: a single static subkey per master key, shared
/// by every tenant. Retained as the decrypt fallback so headers saved
/// before the v2 rollout still decrypt without an operator re-save.
fn derive_otlp_header_key_v1(master_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master_key);
    let mut subkey = Zeroizing::new([0u8; 32]);
    hk.expand(OTLP_HEADER_AEAD_LABEL, subkey.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// v2 per-tenant OTLP subkey: the `user_id` bytes are the HKDF `info`, so
/// the subkey is unique per tenant. Deterministic; encrypt and decrypt
/// derive it identically.
fn derive_otlp_header_key_v2(master_key: &[u8], user_id: Uuid) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(OTLP_HEADER_AEAD_LABEL_V2), master_key);
    let mut subkey = Zeroizing::new([0u8; 32]);
    hk.expand(user_id.as_bytes(), subkey.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// AAD = the 16 raw bytes of the owning tenant's `user_id`. Binds the ciphertext
/// to one tenant so a row can't be transposed between users.
fn otlp_header_aad(user_id: Uuid) -> [u8; 16] {
    *user_id.as_bytes()
}

/// Load + hex-decode `TALOS_MASTER_KEY`. Returns `None` (caller logs) if the env
/// var is unset or not valid hex.
fn load_master_key_bytes() -> Option<Zeroizing<Vec<u8>>> {
    let hex_str = Zeroizing::new(std::env::var("TALOS_MASTER_KEY").ok()?);
    hex::decode(hex_str.trim()).ok().map(Zeroizing::new)
}

/// Encrypt OTLP auth headers (a JSON string) for storage. Returns
/// `(ciphertext, nonce)` for the `auth_headers_encrypted` / `auth_headers_nonce`
/// columns. Called by the GraphQL write path. Errors (opaque string — never the
/// plaintext) if `TALOS_MASTER_KEY` is unavailable or encryption fails.
pub fn encrypt_otlp_auth_headers(
    plaintext: &str,
    user_id: Uuid,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let master_key = load_master_key_bytes().ok_or("TALOS_MASTER_KEY is unset or not valid hex")?;
    encrypt_otlp_auth_headers_with_master_key(plaintext, user_id, &master_key)
}

/// Decrypt OTLP auth headers stored by [`encrypt_otlp_auth_headers`]. Returns the
/// JSON string. Called by the read path. Fails closed (opaque error) on a wrong
/// key, corrupted ciphertext, AAD/tenant mismatch, or bad nonce length.
pub fn decrypt_otlp_auth_headers(
    ciphertext: &[u8],
    nonce: &[u8],
    user_id: Uuid,
) -> Result<Zeroizing<String>, String> {
    let master_key = load_master_key_bytes().ok_or("TALOS_MASTER_KEY is unset or not valid hex")?;
    decrypt_otlp_auth_headers_with_master_key(ciphertext, nonce, user_id, &master_key)
}

/// Encryption core taking the master key explicitly (env-free, so the crypto
/// round-trip is unit-testable without touching the process environment).
fn encrypt_otlp_auth_headers_with_master_key(
    plaintext: &str,
    user_id: Uuid,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use rand::RngCore;
    // v2: per-tenant key derivation (user_id folded into the HKDF info).
    let subkey = derive_otlp_header_key_v2(master_key, user_id);
    let cipher =
        Aes256Gcm::new_from_slice(subkey.as_slice()).map_err(|e| format!("cipher init: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let aad = otlp_header_aad(user_id);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decryption core taking the master key explicitly (env-free; see the encrypt
/// core).
fn decrypt_otlp_auth_headers_with_master_key(
    ciphertext: &[u8],
    nonce: &[u8],
    user_id: Uuid,
    master_key: &[u8],
) -> Result<Zeroizing<String>, String> {
    if nonce.len() != 12 {
        return Err(format!(
            "nonce wrong length (expected 12, got {})",
            nonce.len()
        ));
    }
    let aad = otlp_header_aad(user_id);
    // Try the v2 per-tenant key first, then fall back to the v1 static key
    // so headers saved before the v2 rollout still decrypt without an
    // operator re-save. AES-GCM's tag makes the extra attempt safe — a
    // wrong key cannot forge a passing tag; `aad` is bound on each attempt.
    // Hold the decrypted bytes (auth headers carry `Bearer` tokens) in
    // Zeroizing so the buffer is wiped on drop, including the UTF-8 error
    // branch below.
    let mut decrypted: Option<Zeroizing<Vec<u8>>> = None;
    for subkey in [
        derive_otlp_header_key_v2(master_key, user_id),
        derive_otlp_header_key_v1(master_key),
    ] {
        let cipher = Aes256Gcm::new_from_slice(subkey.as_slice())
            .map_err(|e| format!("cipher init: {e}"))?;
        if let Ok(pt) = cipher.decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            decrypted = Some(Zeroizing::new(pt));
            break;
        }
    }
    let plaintext = decrypted.ok_or_else(|| {
        "decrypt failed — wrong key, corrupted data, or tenant (AAD) mismatch".to_string()
    })?;
    let s = std::str::from_utf8(&plaintext)
        .map_err(|_| "decrypted bytes are not valid UTF-8".to_string())?;
    Ok(Zeroizing::new(s.to_string()))
}

#[cfg(test)]
mod otlp_header_crypto_tests {
    use super::*;

    fn master_key() -> Vec<u8> {
        vec![0x11u8; 32]
    }

    #[test]
    fn round_trip_with_matching_user_succeeds() {
        let user = Uuid::new_v4();
        let headers = r#"{"authorization":"Bearer abc","x-tenant":"acme"}"#;
        let (ct, nonce) =
            encrypt_otlp_auth_headers_with_master_key(headers, user, &master_key()).unwrap();
        let out =
            decrypt_otlp_auth_headers_with_master_key(&ct, &nonce, user, &master_key()).unwrap();
        assert_eq!(&*out, headers);
    }

    #[test]
    fn decrypt_with_different_user_fails_aad_mismatch() {
        let user = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert_ne!(user, other);
        let (ct, nonce) =
            encrypt_otlp_auth_headers_with_master_key("{}", user, &master_key()).unwrap();
        // Transposing the blob to another tenant must fail closed.
        let err = decrypt_otlp_auth_headers_with_master_key(&ct, &nonce, other, &master_key())
            .unwrap_err();
        assert!(err.contains("AAD") || err.contains("mismatch"), "got {err}");
    }

    #[test]
    fn decrypt_with_wrong_master_key_fails() {
        let user = Uuid::new_v4();
        let (ct, nonce) =
            encrypt_otlp_auth_headers_with_master_key("{}", user, &master_key()).unwrap();
        let wrong = vec![0x22u8; 32];
        assert!(decrypt_otlp_auth_headers_with_master_key(&ct, &nonce, user, &wrong).is_err());
    }

    #[test]
    fn derived_subkey_differs_from_raw_master_key() {
        let mk = master_key();
        let subkey = derive_otlp_header_key_v1(&mk);
        assert_ne!(
            &subkey[..],
            &mk[..],
            "subkey must not equal the raw master key"
        );
        assert_eq!(
            subkey,
            derive_otlp_header_key_v1(&mk),
            "derivation is deterministic"
        );
        // v2 per-tenant derivation: distinct tenants derive distinct keys,
        // each differing from the v1 static key (finding #1).
        let a = derive_otlp_header_key_v2(&mk, Uuid::new_v4());
        let b = derive_otlp_header_key_v2(&mk, Uuid::new_v4());
        assert_ne!(&*a, &*b, "different tenants must derive different keys");
        assert_ne!(
            &*a, &*subkey,
            "v2 per-tenant key must differ from v1 static"
        );
    }

    #[test]
    fn legacy_v1_headers_decrypt_via_fallback() {
        // Headers saved under the v1 static key (pre-v2 rollout) must still
        // decrypt through the v2-first fallback.
        let mk = master_key();
        let user = Uuid::new_v4();
        let headers = r#"{"authorization":"Bearer legacy"}"#;

        // Hand-encrypt a v1 blob: static key + user_id AAD.
        let v1_key = derive_otlp_header_key_v1(&mk);
        let cipher = Aes256Gcm::new_from_slice(v1_key.as_slice()).unwrap();
        let nonce = [5u8; 12];
        let aad = otlp_header_aad(user);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: headers.as_bytes(),
                    aad: &aad,
                },
            )
            .unwrap();
        let out = decrypt_otlp_auth_headers_with_master_key(&ct, &nonce, user, &mk).unwrap();
        assert_eq!(&*out, headers);
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let user = Uuid::new_v4();
        let err =
            decrypt_otlp_auth_headers_with_master_key(&[1, 2, 3], &[0u8; 11], user, &master_key())
                .unwrap_err();
        assert!(err.contains("nonce wrong length"), "got {err}");
    }
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
            auth_headers_nonce: Option<Vec<u8>>,
        }
        let settings = sqlx::query_as::<_, SettingsRow>(
            r#"
            SELECT streaming_enabled, otlp_endpoint, otlp_protocol, auth_headers_encrypted, auth_headers_nonce
            FROM user_audit_settings
            WHERE user_id = $1
            "#
        ).bind(user_id).fetch_optional(pool).await.ok()??;

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

        if let (Some(encrypted), Some(nonce)) =
            (settings.auth_headers_encrypted, settings.auth_headers_nonce)
        {
            // L3: decrypt via the canonical helper (HKDF subkey of
            // TALOS_MASTER_KEY + user_id AAD) — the SAME primitive the GraphQL
            // write path encrypts with. Do NOT silently swallow failures: a
            // decrypt error means the exporter would stream WITHOUT auth, which
            // operators must be able to see.
            match decrypt_otlp_auth_headers(&encrypted, &nonce, user_id) {
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
                         headers. Check TALOS_MASTER_KEY, and note that header blobs saved before \
                         the L3 key-realignment (SecretsManager-DEK ciphertext) are not readable \
                         and must be re-saved via update_audit_settings."
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

pub async fn start_audit_ledger_subscriber(nc: Client, db_pool: PgPool) -> Result<()> {
    tracing::info!("Initializing audit ledger subscriber");
    tracing::debug!("Audit ledger subscriber initialisation proceeding");

    let js = jetstream::new(nc);

    // Ensure the stream exists for guaranteed delivery
    let stream_name = "AUDIT_LEDGER";
    let subject = "talos.audit.ledger";
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
    // !v.is_empty())` after each `.ok()`.
    let s3_endpoint = std::env::var("AWS_ENDPOINT_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("MINIO_ENDPOINT")
                .ok()
                .filter(|v| !v.is_empty())
        });
    let s3_client: Option<S3Client> = if let Some(endpoint) = s3_endpoint {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let mut builder = aws_sdk_s3::config::Builder::from(&config).endpoint_url(endpoint);
        // MCP-1073 (2026-05-16): canonical bool-env helper. Pre-fix
        // `== "true"` case-sensitive exact-match — operators using
        // MinIO (a common audit-log target that REQUIRES path-style
        // addressing) who set `=1` / `=yes` / `=on` / `=TRUE` got
        // the FALSE branch silently, breaking bucket addressing with
        // "bucket not found" errors. Same user-visible-bug class as
        // MCP-1072 (ENABLE_HSTS explicit-disable). Sibling drift
        // class to MCP-1060/1064/1065/1066/1072.
        if talos_config::bool_env_or_default("AWS_S3_FORCE_PATH_STYLE", false) {
            builder = builder.force_path_style(true);
        }
        Some(S3Client::from_conf(builder.build()))
    } else {
        None
    };

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
        let bucket = std::env::var("MINIO_BUCKET")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "audit-logs".to_string());
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
                            process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, object_lock).await;
                        }
                    }
                    msg_result = messages.next() => {
                        match msg_result {
                            Some(Ok(msg)) => {
                                batch.push(msg);
                                if batch.len() >= max_batch_size {
                                    process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, object_lock).await;
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
                                    process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache, object_lock).await;
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
            if let Some(tracer) = otlp_cache.get_tracer(user_id, db_pool).await {
                let mut span = tracer.start("audit_event");
                span.set_attribute(KeyValue::new("talos.workflow.id", workflow_id.clone()));
                span.set_attribute(KeyValue::new("talos.execution.id", execution_id.clone()));
                span.set_attribute(KeyValue::new(
                    "talos.crypto.sequence",
                    event["sequence_num"].as_u64().unwrap_or(0) as i64,
                ));
                span.set_attribute(KeyValue::new(
                    "talos.actor",
                    event["actor"].as_str().unwrap_or("unknown").to_string(),
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
                // MCP-1207 (2026-05-17): truncate-then-redact for the
                // OTLP span attribute. Pre-fix `redact_str` walked the
                // full `event["payload"]` (up to ~1 MB — NATS message
                // size cap) and the unbounded result was bound to the
                // span attribute. Two costs: (a) regex pass cost on
                // multi-KB payload runs on every audit event with a
                // configured tracer; (b) OTLP exporters truncate
                // attribute strings inconsistently (the default
                // opentelemetry-sdk per-attribute cap is 32 KiB but
                // varies by exporter), so an over-cap payload silently
                // gets clipped downstream — better to clip it
                // deterministically up front. Cap at 4 KiB: bounds the
                // regex pass cost AND fits comfortably inside every
                // known OTLP exporter's per-attribute limit, while
                // preserving enough payload context for human triage
                // through the trace UI. Same truncate-first-before-
                // redact discipline as MCP-1160/1161/1165/1167 on the
                // DB persistence sites; here it's the telemetry
                // boundary.
                const MAX_OTLP_PAYLOAD_PREVIEW_BYTES: usize = 4096;
                let payload_str = event["payload"].as_str().unwrap_or("");
                let truncated_preview: &str = if payload_str.len() > MAX_OTLP_PAYLOAD_PREVIEW_BYTES
                {
                    talos_text_util::truncate_at_char_boundary(
                        payload_str,
                        MAX_OTLP_PAYLOAD_PREVIEW_BYTES,
                    )
                } else {
                    payload_str
                };
                span.set_attribute(KeyValue::new(
                    "talos.payload",
                    talos_dlp_provider::redact_str(truncated_preview),
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
