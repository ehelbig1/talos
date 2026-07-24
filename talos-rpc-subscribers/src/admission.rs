//! Typed admission gate for signed-RPC subscribers.
//!
//! Every request/reply subscriber must run the same Tier-0 sequence
//! before touching state: parse → per-protocol `verify()` (HMAC +
//! freshness) → cross-replica replay check → process-local nonce
//! record. Pre-extraction (2026-07-24) that ordering was replicated by
//! convention at seven call sites in `lib.rs`; a new subscriber could
//! compile with a step missing or reordered, and review was the only
//! net. This module makes the ordering a COMPILE-TIME guarantee:
//!
//! * [`Admitted<T>`] has a private field — the only constructor is
//!   [`admit_from_bytes`], which runs the full sequence in the correct
//!   order. Handler business logic that takes `Admitted<T>` (or calls
//!   `.into_inner()`) therefore cannot receive a payload that skipped
//!   or reordered a step.
//! * Each protocol declares its identity once via [`AdmittableRpc`]:
//!   the WIRE subject (cross-replica replay key + metric label) and
//!   the canonical SIGNING subject (process-local nonce-cache key) are
//!   distinct strings per protocol — conflating them would silently
//!   split the replay domains, so the trait forces both to be named.
//!
//! What deliberately STAYS per-protocol at the call sites (see
//! `kernel.rs` module docs): reply-inbox semantics, the typed error
//! reply for each [`AdmitError`] arm, log-message wording, and the
//! metric outcome tag. Those are protocol surface, not admission
//! logic — and keeping the `match` at each site preserves the
//! greppability the pre-extraction comment asked for (`admit_from_bytes
//! ::<GraphSearchRequest>` is exactly as searchable as the old inline
//! `req.verify()` block).

use serde::de::DeserializeOwned;

/// Per-protocol identity + verification hook for the admission gate.
///
/// Implementations are one-liners that delegate to the protocol's
/// existing `verify()` — the HMAC/freshness logic itself stays in
/// `talos_memory::*_rpc` where it is reviewed and tested.
pub(crate) trait AdmittableRpc: DeserializeOwned {
    /// NATS wire subject (e.g. `"talos.graph.search"`) — the
    /// cross-replica replay-guard key prefix and the `talos_rpc`
    /// metric label.
    const WIRE_SUBJECT: &'static str;
    /// Canonical signing subject (e.g. `"graph_rpc"`) — the
    /// process-local two-generation nonce-cache key. Distinct from the
    /// wire subject by design; see `talos_memory::rpc_auth`.
    const SIGNING_SUBJECT: &'static str;
    /// Per-protocol HMAC + freshness verification.
    fn verify_signature(&self) -> bool;
    fn actor_id(&self) -> uuid::Uuid;
    fn nonce(&self) -> &str;
}

/// Proof that a request passed parse → verify → cross-replica replay →
/// process-local nonce record, in that order. Private field: the only
/// constructor is [`admit_from_bytes`].
pub(crate) struct Admitted<T>(T);

impl<T> Admitted<T> {
    /// Consume the proof and take ownership of the request. Admission
    /// has already happened by construction — this exists for handlers
    /// that move fields out of the request.
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Admitted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Why admission failed. Each subscriber maps these to its protocol's
/// typed error reply and metric outcome tag (`"invalid"` /
/// `"unauthorized"` / `"replay"`) at the call site.
pub(crate) enum AdmitError {
    /// Payload did not deserialize; carries the parse error text for
    /// the protocol's `InvalidInput`-style reply (parse errors are not
    /// sensitive — they describe the caller's own malformed bytes).
    Malformed(String),
    /// HMAC/freshness verification failed OR the cross-replica replay
    /// guard rejected the nonce. Collapsed into one arm deliberately —
    /// the pre-extraction sites logged and replied identically for
    /// both, and distinguishing them for a caller would give an
    /// on-wire attacker an oracle.
    Unauthorized,
    /// Process-local nonce cache saw this nonce already.
    Replay,
}

/// THE admission chokepoint. Parse the payload, verify HMAC +
/// freshness, run the cross-replica replay guard, then record the
/// nonce in the process-local cache — in that order, fail-closed at
/// each step. Returns the only constructible [`Admitted<T>`].
pub(crate) async fn admit_from_bytes<T: AdmittableRpc>(
    payload: &[u8],
) -> Result<Admitted<T>, AdmitError> {
    let req: T =
        serde_json::from_slice(payload).map_err(|e| AdmitError::Malformed(e.to_string()))?;
    if !req.verify_signature()
        || !crate::crossreplica_replay_ok(T::WIRE_SUBJECT, req.actor_id(), req.nonce()).await
    {
        return Err(AdmitError::Unauthorized);
    }
    if !talos_memory::rpc_auth::check_and_record_nonce(
        T::SIGNING_SUBJECT,
        req.actor_id(),
        req.nonce(),
    ) {
        return Err(AdmitError::Replay);
    }
    Ok(Admitted(req))
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    // A minimal in-crate protocol standing in for the real ones, so the
    // gate's ordering and fail-closed arms are pinned without NATS or a
    // registered HMAC key.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct FakeReq {
        actor_id: uuid::Uuid,
        nonce: String,
        valid: bool,
    }

    impl AdmittableRpc for FakeReq {
        const WIRE_SUBJECT: &'static str = "talos.test.admission";
        const SIGNING_SUBJECT: &'static str = "admission_test_rpc";
        fn verify_signature(&self) -> bool {
            self.valid
        }
        fn actor_id(&self) -> uuid::Uuid {
            self.actor_id
        }
        fn nonce(&self) -> &str {
            &self.nonce
        }
    }

    fn canonical_nonce() -> String {
        // 32 lowercase hex chars — the canonical-nonce shape the
        // process-local cache requires (MCP-1137 gate).
        format!("{:032x}", rand_like())
    }

    fn rand_like() -> u128 {
        // Unique-enough per call for cache-key isolation across tests.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }

    #[tokio::test]
    async fn malformed_payload_is_rejected_before_verification() {
        let err = admit_from_bytes::<FakeReq>(b"not json").await;
        assert!(matches!(err, Err(AdmitError::Malformed(_))));
    }

    #[tokio::test]
    async fn failed_verification_is_unauthorized() {
        let req = FakeReq {
            actor_id: uuid::Uuid::new_v4(),
            nonce: canonical_nonce(),
            valid: false,
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let err = admit_from_bytes::<FakeReq>(&bytes).await;
        assert!(matches!(err, Err(AdmitError::Unauthorized)));
    }

    #[tokio::test]
    async fn admitted_once_then_replay_rejected() {
        let req = FakeReq {
            actor_id: uuid::Uuid::new_v4(),
            nonce: canonical_nonce(),
            valid: true,
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let first = admit_from_bytes::<FakeReq>(&bytes).await;
        assert!(first.is_ok(), "first presentation must be admitted");
        // Same nonce again — the process-local cache must reject it.
        let second = admit_from_bytes::<FakeReq>(&bytes).await;
        assert!(matches!(second, Err(AdmitError::Replay)));
    }

    #[tokio::test]
    async fn rejected_verification_does_not_burn_the_nonce() {
        // A forged message must not be able to pre-poison the nonce
        // cache and DoS the legitimate sender: verification failure
        // returns BEFORE the nonce is recorded.
        let nonce = canonical_nonce();
        let actor = uuid::Uuid::new_v4();
        let forged = FakeReq {
            actor_id: actor,
            nonce: nonce.clone(),
            valid: false,
        };
        let bytes = serde_json::to_vec(&forged).expect("serialize");
        assert!(matches!(
            admit_from_bytes::<FakeReq>(&bytes).await,
            Err(AdmitError::Unauthorized)
        ));
        let genuine = FakeReq {
            actor_id: actor,
            nonce,
            valid: true,
        };
        let bytes = serde_json::to_vec(&genuine).expect("serialize");
        assert!(
            admit_from_bytes::<FakeReq>(&bytes).await.is_ok(),
            "legitimate message must still be admitted after a forged \
             attempt with the same nonce was rejected"
        );
    }

    #[tokio::test]
    async fn into_inner_and_deref_expose_the_request() {
        let req = FakeReq {
            actor_id: uuid::Uuid::new_v4(),
            nonce: canonical_nonce(),
            valid: true,
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let admitted = admit_from_bytes::<FakeReq>(&bytes)
            .await
            .ok()
            .expect("admitted");
        assert_eq!(admitted.actor_id(), req.actor_id); // Deref
        let owned = admitted.into_inner();
        assert_eq!(owned.nonce, req.nonce);
    }
}
