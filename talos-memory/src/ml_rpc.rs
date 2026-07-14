//! Signed NATS-RPC protocol for `model::predict` (RFC 0011 P2c).
//!
//! Workers publish [`SUBJECT_ML_PREDICT`] with an [`MlPredictRequest`];
//! the controller resolves the named model's PROMOTED version under the
//! signed `user_id`'s tenancy, runs the fast backend (P2: knn-pgvector,
//! local embeddings), and replies with per-input predictions. READ-ONLY:
//! this primitive never writes — dataset appends stay controller-side
//! (the DISTILL lifecycle hook) or on the MCP surface.
//!
//! Batch-first: a single predict is a batch of one. Batching amortizes
//! the NATS round-trip and the model resolution for the per-email
//! workflows this serves.
//!
//! Security invariants (docs/platform-primitive-checklist.md walked
//! 2026-07-11; every item mapped):
//! - `user_id` (tenancy) and `model_name` (ROUTING — the
//!   `integration_name`-gap class) are inside the signed body; an
//!   on-wire attacker cannot redirect a prediction to another tenant's
//!   model without invalidating the signature. `actor_id` is bound at
//!   the `rpc_auth` layer like every sibling.
//! - Hand-built canonical bytes: LE numerics, length-prefixed
//!   variable-width fields (injective), fixed tag byte with a
//!   compile-time uniqueness guard.
//! - Structural caps validated at sign time AND inside `verify()`
//!   (cheap-gate-first, before the MAC compute) AND re-checked by the
//!   subscriber (defense in depth).
//! - No floats anywhere in the signed body (confidence is
//!   response-side only), so NaN canonicalization cannot arise.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::rpc_auth;

pub const SUBJECT_ML_PREDICT: &str = "talos.ml.predict";
/// Distinct from every other RPC subject so nonce-cache entries can't
/// collide across protocols.
pub const SUBJECT_NAME: &str = "ml_rpc";

/// Per-request input cap. Sized for the organizer-style batch (≤ 25
/// emails per run) with headroom; a fan-out that needs more issues
/// multiple requests and pays the (small) round-trip each time.
pub const MAX_INPUTS: usize = 32;
/// Per-input byte cap. Feature text for classification is
/// subject+from+snippet (< 2 KiB in practice); 16 KiB bounds the
/// embedding + signing cost without constraining legitimate use.
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
/// Model names are operator-chosen identifiers, not content.
pub const MAX_MODEL_NAME_LEN: usize = 128;
/// Controller-side concurrency cap (matches graph_rpc — both fan out
/// to per-request embedding + pgvector work).
pub const MAX_IN_FLIGHT: usize = 8;
/// Worker-side NATS request timeout. Worst case = 32 cold local embeds
/// (~80 ms each) + knn queries; 10 s bounds a stalled controller
/// without zombie-ing the module for the full execution timeout.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
/// Subscriber-side cap wrapping ALL DB/embedding work for one request —
/// a stalled Postgres must not hold an in-flight permit indefinitely
/// (the zombie-permit gap the checklist flags in the existing family).
pub const SUBSCRIBER_OP_TIMEOUT_MS: u64 = 8_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlPredictRequest {
    /// Runtime actor identity (rpc_auth-bound; budget/audit trail).
    pub actor_id: Uuid,
    /// Tenancy principal: the model is resolved under THIS user's read
    /// scope. Signed — see `sign_body_bytes`.
    pub user_id: Uuid,
    /// Registry model NAME (resolution is personal-first deterministic).
    /// Signed — a routing field, exactly the class the checklist calls
    /// out via the `JobRequest.integration_name` gap.
    pub model_name: String,
    /// Feature texts to classify, one prediction slot each.
    pub inputs: Vec<String>,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
    /// RFC 0010 P2: signer identity (empty under HMAC, worker id under
    /// Ed25519).
    #[serde(default)]
    pub worker_id: String,
    /// Unsigned scheme hint: 0 = HMAC, 1 = Ed25519.
    #[serde(default)]
    pub crypto_scheme: u8,
}

/// Variant tag byte. Future ml_rpc operations claim fresh bytes and
/// extend the guard below.
const TAG_ML_PREDICT: u8 = b'P';
/// Few-shot corrections fetch (teacher-improvement loop).
const TAG_ML_FEWSHOT: u8 = b'F';

/// Compile-time uniqueness guard (family pattern).
const _ML_TAG_UNIQUENESS_GUARD: [u8; 2] = {
    let tags = [TAG_ML_PREDICT, TAG_ML_FEWSHOT];
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "ml_rpc tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Length-prefix helper: u32 LE byte length + bytes. Injective for
/// variable-width sequences (two different input lists can never
/// serialize to the same bytes).
fn lp(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Canonical signed bytes.
///
/// WIRE-FORMAT STABILITY: field order is LOAD-BEARING and APPEND-ONLY.
/// Reordering or inserting fields invalidates every in-flight signature
/// during a rolling deploy. New fields append at the END.
///
///   timestamp_ms (i64 LE) || TAG_ML_PREDICT (1B) || user_id (16B)
///   || lp(model_name) || input_count (u32 LE) || lp(input)*
fn sign_body_bytes(
    user_id: Uuid,
    model_name: &str,
    inputs: &[String],
    timestamp_ms: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        64 + model_name.len() + inputs.iter().map(|i| i.len() + 4).sum::<usize>(),
    );
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(TAG_ML_PREDICT);
    buf.extend_from_slice(user_id.as_bytes());
    lp(&mut buf, model_name);
    buf.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for input in inputs {
        lp(&mut buf, input);
    }
    buf
}

/// Structural caps, shared by sign-time, verify-time, and the
/// subscriber's defense-in-depth re-check.
pub fn validate_structure(model_name: &str, inputs: &[String]) -> bool {
    if model_name.is_empty()
        || model_name.len() > MAX_MODEL_NAME_LEN
        || !model_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return false;
    }
    if inputs.is_empty() || inputs.len() > MAX_INPUTS {
        return false;
    }
    inputs
        .iter()
        .all(|i| !i.trim().is_empty() && i.len() <= MAX_INPUT_BYTES)
}

impl MlPredictRequest {
    pub fn new_signed(
        actor_id: Uuid,
        user_id: Uuid,
        model_name: String,
        inputs: Vec<String>,
    ) -> Option<Self> {
        if !validate_structure(&model_name, &inputs) {
            return None;
        }
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body_bytes = sign_body_bytes(user_id, &model_name, &inputs, timestamp_ms);
        let (signature, worker_id, crypto_scheme) =
            rpc_auth::sign_rpc(SUBJECT_NAME, actor_id, &nonce, &body_bytes)?;
        Some(Self {
            actor_id,
            user_id,
            model_name,
            inputs,
            timestamp_ms,
            nonce,
            signature,
            worker_id,
            crypto_scheme,
        })
    }

    /// Signature + freshness + structural caps. Cheap gates first. The
    /// subscriber ALSO calls `rpc_auth::check_and_record_nonce` after
    /// this (verify/nonce split, family convention).
    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        if !validate_structure(&self.model_name, &self.inputs) {
            return false;
        }
        let body_bytes = sign_body_bytes(
            self.user_id,
            &self.model_name,
            &self.inputs,
            self.timestamp_ms,
        );
        rpc_auth::verify_rpc(
            SUBJECT_NAME,
            self.actor_id,
            &self.nonce,
            &body_bytes,
            &self.worker_id,
            &self.signature,
            self.crypto_scheme,
        )
    }
}

/// One prediction slot. `None` in the reply's vector = the backend
/// abstained for that input (caller falls back to its LLM branch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePrediction {
    /// Predicted label (classification) — JSON-shaped output for other
    /// task types when they arrive.
    pub label: String,
    /// Winning share of (damped) vote weight, comparable against the
    /// model's configured threshold ONLY when calibrated under the same
    /// voting scheme (metrics_json.voting).
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlPredictReply {
    /// Parallel to the request's `inputs`.
    pub predictions: Vec<Option<WirePrediction>>,
    pub model_version: i32,
    pub backend: String,
}

/// Error taxonomy — kept coarse so replies can't leak schema or other
/// tenants' existence (`NotFound` covers absent AND foreign models).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlRpcError {
    Unauthorized,
    /// Absent, foreign, or invisible model — deliberately one variant.
    NotFound,
    /// Model exists but has no promoted version to serve.
    NotPromoted,
    /// Promoted backend can't serve (dataset gone, unsupported backend,
    /// embedder down) — the RFC's loud lifecycle failure mode.
    NotAvailable,
    Invalid,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlPredictResponse {
    Ok(MlPredictReply),
    Err(MlRpcError),
}

// ─── talos.ml.fewshot — correction examples for the LLM teacher leg ────────
//
// The distillation loop's missing half: human corrections fix the MODEL's
// training data, but the LLM TEACHER kept mislabeling the same boundary and
// re-poisoning production labels faster than reviews could correct them
// (observed 2026-07-14: 49 of 56 disagreement reviews were the same
// to_read/archive boundary the teacher got wrong). This op lets the
// classifier templates fetch K recent human-verified (features, label)
// pairs for THEIR model and inject them as few-shot anchors into the LLM
// fallback prompt — the teacher learns from the same reviews the model does.
//
// READ-ONLY like predict; separate SUBJECT + SUBJECT_NAME so nonce-cache
// entries and canonical bytes can never collide with the predict op.

pub const SUBJECT_ML_FEWSHOT: &str = "talos.ml.fewshot";
/// Distinct nonce-cache namespace (checklist §2).
pub const SUBJECT_NAME_FEWSHOT: &str = "ml_fewshot_rpc";

/// Total examples per request. Few-shot anchors saturate fast — beyond a
/// handful they add prompt cost, not signal.
pub const MAX_FEWSHOT_K: u32 = 8;
/// Server-side truncation of each example's features text before it goes
/// on the wire. Anchors need the discriminative head of the text, not the
/// full email; the cap also bounds reply size and the prompt-injection
/// surface a stored example can carry into future prompts.
pub const MAX_FEWSHOT_FEATURE_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlFewShotRequest {
    /// Runtime actor identity (rpc_auth-bound; budget/audit trail).
    pub actor_id: Uuid,
    /// Tenancy principal — the model resolves under THIS user. Signed.
    pub user_id: Uuid,
    /// Registry model NAME (routing — signed, integration_name-gap class).
    pub model_name: String,
    /// Max examples to return (1..=MAX_FEWSHOT_K). Signed.
    pub k: u32,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub worker_id: String,
    #[serde(default)]
    pub crypto_scheme: u8,
}

/// Canonical signed bytes for the few-shot op.
///
/// WIRE-FORMAT STABILITY: field order is LOAD-BEARING and APPEND-ONLY.
/// New fields append at the END.
///
///   timestamp_ms (i64 LE) || TAG_ML_FEWSHOT (1B) || user_id (16B)
///   || lp(model_name) || k (u32 LE)
fn fewshot_sign_body_bytes(user_id: Uuid, model_name: &str, k: u32, timestamp_ms: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + model_name.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(TAG_ML_FEWSHOT);
    buf.extend_from_slice(user_id.as_bytes());
    lp(&mut buf, model_name);
    buf.extend_from_slice(&k.to_le_bytes());
    buf
}

/// Structural caps, shared by sign-time, verify-time, and the subscriber's
/// defense-in-depth re-check.
pub fn validate_fewshot_structure(model_name: &str, k: u32) -> bool {
    if model_name.is_empty()
        || model_name.len() > MAX_MODEL_NAME_LEN
        || !model_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return false;
    }
    (1..=MAX_FEWSHOT_K).contains(&k)
}

impl MlFewShotRequest {
    pub fn new_signed(actor_id: Uuid, user_id: Uuid, model_name: String, k: u32) -> Option<Self> {
        if !validate_fewshot_structure(&model_name, k) {
            return None;
        }
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body_bytes = fewshot_sign_body_bytes(user_id, &model_name, k, timestamp_ms);
        let (signature, worker_id, crypto_scheme) =
            rpc_auth::sign_rpc(SUBJECT_NAME_FEWSHOT, actor_id, &nonce, &body_bytes)?;
        Some(Self {
            actor_id,
            user_id,
            model_name,
            k,
            timestamp_ms,
            nonce,
            signature,
            worker_id,
            crypto_scheme,
        })
    }

    /// Signature + freshness + structural caps. Cheap gates first; the
    /// subscriber ALSO calls `check_and_record_nonce` after this.
    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        if !validate_fewshot_structure(&self.model_name, self.k) {
            return false;
        }
        let body_bytes =
            fewshot_sign_body_bytes(self.user_id, &self.model_name, self.k, self.timestamp_ms);
        rpc_auth::verify_rpc(
            SUBJECT_NAME_FEWSHOT,
            self.actor_id,
            &self.nonce,
            &body_bytes,
            &self.worker_id,
            &self.signature,
            self.crypto_scheme,
        )
    }
}

/// One human-verified anchor: truncated features text + its corrected label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFewShotExample {
    pub features_text: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlFewShotReply {
    /// Class-balanced, most-recent-first. May be EMPTY (a fresh model has
    /// no corrections yet) — that is a success, not an error; callers
    /// proceed with an unaugmented prompt.
    pub examples: Vec<WireFewShotExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlFewShotResponse {
    Ok(MlFewShotReply),
    Err(MlRpcError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_key() {
        // Same helper the sibling signed-roundtrip tests use.
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x11u8; 32]));
    }

    fn req() -> MlPredictRequest {
        MlPredictRequest::new_signed(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            "inbox-classifier-personal".into(),
            vec!["Subject: hi\nFrom: a@b.c\nSnippet: hello".into()],
        )
        .expect("signable")
    }

    #[test]
    fn round_trip_verifies() {
        setup_key();
        assert!(req().verify());
    }

    #[test]
    fn structural_caps_reject_at_sign_time() {
        setup_key();
        let mk = |name: &str, inputs: Vec<String>| {
            MlPredictRequest::new_signed(
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                name.into(),
                inputs,
            )
        };
        assert!(mk("", vec!["x".into()]).is_none(), "empty name");
        assert!(mk("bad name!", vec!["x".into()]).is_none(), "charset");
        assert!(mk(&"n".repeat(200), vec!["x".into()]).is_none(), "name len");
        assert!(mk("m", vec![]).is_none(), "no inputs");
        assert!(mk("m", vec![" ".into()]).is_none(), "blank input");
        assert!(
            mk("m", vec!["x".repeat(MAX_INPUT_BYTES + 1)]).is_none(),
            "oversize input"
        );
        assert!(
            mk("m", (0..MAX_INPUTS + 1).map(|i| i.to_string()).collect()).is_none(),
            "too many inputs"
        );
    }

    #[test]
    fn tampered_identity_fields_fail_verify() {
        setup_key();
        // user_id (tenancy) is signed.
        let mut r = req();
        r.user_id = Uuid::from_u128(99);
        assert!(!r.verify(), "user_id swap must fail");
        // model_name (routing) is signed.
        let mut r = req();
        r.model_name = "someone-elses-model".into();
        assert!(!r.verify(), "model_name swap must fail");
        // inputs are signed.
        let mut r = req();
        r.inputs[0] = "Subject: different".into();
        assert!(!r.verify(), "input swap must fail");
        // appending an input is caught (count is signed).
        let mut r = req();
        r.inputs.push("extra".into());
        assert!(!r.verify(), "input append must fail");
        // actor swap is caught at the rpc_auth layer.
        let mut r = req();
        r.actor_id = Uuid::from_u128(42);
        assert!(!r.verify(), "actor swap must fail");
    }

    fn fewshot_req() -> MlFewShotRequest {
        MlFewShotRequest::new_signed(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            "inbox-classifier-personal".into(),
            6,
        )
        .expect("signable")
    }

    #[test]
    fn fewshot_round_trip_verifies() {
        setup_key();
        assert!(fewshot_req().verify());
    }

    #[test]
    fn fewshot_structural_caps_reject_at_sign_time() {
        setup_key();
        let mk = |name: &str, k: u32| {
            MlFewShotRequest::new_signed(Uuid::from_u128(1), Uuid::from_u128(2), name.into(), k)
        };
        assert!(mk("", 4).is_none(), "empty name");
        assert!(mk("bad name!", 4).is_none(), "charset");
        assert!(mk(&"n".repeat(200), 4).is_none(), "name len");
        assert!(mk("m", 0).is_none(), "k zero");
        assert!(mk("m", MAX_FEWSHOT_K + 1).is_none(), "k over cap");
    }

    #[test]
    fn fewshot_tampered_identity_fields_fail_verify() {
        setup_key();
        // user_id (tenancy) is signed.
        let mut r = fewshot_req();
        r.user_id = Uuid::from_u128(99);
        assert!(!r.verify(), "user_id swap must fail");
        // model_name (routing) is signed.
        let mut r = fewshot_req();
        r.model_name = "someone-elses-model".into();
        assert!(!r.verify(), "model_name swap must fail");
        // k is signed (an attacker must not inflate the fetch).
        let mut r = fewshot_req();
        r.k = 8;
        assert!(!r.verify(), "k swap must fail");
        // actor swap is caught at the rpc_auth layer.
        let mut r = fewshot_req();
        r.actor_id = Uuid::from_u128(42);
        assert!(!r.verify(), "actor swap must fail");
    }

    #[test]
    fn fewshot_and_predict_ops_are_cryptographically_disjoint() {
        setup_key();
        // A signature minted for the PREDICT op must not verify on a
        // FEWSHOT request even with identical identity fields — the ops
        // differ in both the canonical tag byte AND the rpc_auth
        // SUBJECT_NAME namespace (either alone would suffice; both is
        // the family's defense in depth).
        let p = req();
        let mut f = fewshot_req();
        f.timestamp_ms = p.timestamp_ms;
        f.nonce = p.nonce.clone();
        f.signature = p.signature.clone();
        f.worker_id = p.worker_id.clone();
        f.crypto_scheme = p.crypto_scheme;
        assert!(!f.verify(), "cross-op signature transplant must fail");
        // And the canonical bytes themselves cannot collide (tag byte).
        let pb = sign_body_bytes(Uuid::from_u128(2), "m", &[], 7);
        let fb = fewshot_sign_body_bytes(Uuid::from_u128(2), "m", 0, 7);
        assert_ne!(pb, fb, "tag byte separates op byte-streams");
    }

    #[test]
    fn wire_format_is_deterministic_and_injective_on_boundaries() {
        // Same logical content → identical bytes.
        let a = sign_body_bytes(Uuid::from_u128(2), "m", &["ab".into(), "c".into()], 7);
        let b = sign_body_bytes(Uuid::from_u128(2), "m", &["ab".into(), "c".into()], 7);
        assert_eq!(a, b);
        // Boundary shifting between adjacent inputs changes the bytes
        // (length prefixes make the encoding injective).
        let c = sign_body_bytes(Uuid::from_u128(2), "m", &["a".into(), "bc".into()], 7);
        assert_ne!(a, c, "\"ab\",\"c\" must not collide with \"a\",\"bc\"");
        // Model-name/input boundary is likewise prefixed.
        let d = sign_body_bytes(Uuid::from_u128(2), "ma", &["b".into()], 7);
        let e = sign_body_bytes(Uuid::from_u128(2), "m", &["ab".into()], 7);
        assert_ne!(d, e);
    }
}
