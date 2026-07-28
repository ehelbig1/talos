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
    /// Per-protocol HMAC/Ed25519 + freshness + structural verification.
    ///
    /// Named `verify_classified` (not `verify_signature`) since #603: the
    /// return type changed from `bool` to a `Result`, and renaming forces
    /// every implementation and every caller through the compiler rather
    /// than letting some future `bool`-shaped helper slot in silently.
    fn verify_classified(&self) -> Result<(), talos_memory::rpc_auth::VerifyFailure>;
    fn actor_id(&self) -> uuid::Uuid;
    fn nonce(&self) -> &str;
    /// Self-reported signer identity — empty under the legacy HMAC scheme,
    /// the worker's id under Ed25519. Used ONLY to look up that worker's
    /// reported build for the rejection log's skew hint. Untrusted by
    /// definition (it is the claim under test), which is fine: a forged id
    /// simply misses the cache and yields the "unverifiable" wording.
    fn worker_id(&self) -> &str;
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

/// The controller-side classification of an `Unauthorized` admission
/// failure. See [`AdmitError::Unauthorized`] for where it may and may not
/// travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// One of the per-protocol `verify()` gates rejected the request.
    Verify(talos_memory::rpc_auth::VerifyFailure),
    /// The request verified, but another controller replica had already seen
    /// this nonce (the shared-store replay guard).
    CrossReplicaReplay,
}

impl RejectReason {
    /// Stable snake_case token for the rejection log. Same contract as
    /// `VerifyFailure::as_str` — append, never rename.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Verify(f) => f.as_str(),
            Self::CrossReplicaReplay => "cross_replica_replay",
        }
    }

    /// Whether a build-skew hint is worth computing for this reason.
    ///
    /// ONLY `bad_signature`. Stale is a clock, oversized/non-finite is a
    /// malformed payload, unknown-signer is a key-registration gap, and a
    /// cross-replica replay is by definition a request that ALREADY verified
    /// — attaching a skew sentence to any of them would manufacture the
    /// false lead this change exists to remove.
    pub(crate) fn is_skew_candidate(self) -> bool {
        matches!(
            self,
            Self::Verify(talos_memory::rpc_auth::VerifyFailure::BadSignature)
        )
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
    ///
    /// **`reason` DOES NOT CHANGE THAT.** It is a CONTROLLER-SIDE LOG FIELD
    /// and nothing else. The collapse above is still deliberate and still
    /// load-bearing: the wire reply is byte-identical for every reason (a
    /// caller cannot tell `stale` from `bad_signature` from
    /// `cross_replica_replay`), because splitting them for a caller hands an
    /// on-wire attacker an oracle — they could map the freshness window and
    /// confirm key validity as two independent probes. `reason` exists only
    /// because the OPERATOR, reading the controller's own logs, was
    /// previously given the same zero information as the attacker. Every
    /// caller-facing value on this path routes through
    /// `crate::caller_facing_unauthorized`, which takes the reason and drops
    /// it; `unauthorized_reply_bytes_are_reason_independent` pins that.
    Unauthorized { reason: RejectReason },
    /// Process-local nonce cache saw this nonce already.
    Replay,
}

/// The extra fields every `Unauthorized` rejection log gains. Built once per
/// rejection, on the rejection path only.
pub(crate) struct RejectDiagnostics {
    /// Our own stable taxonomy token — never anything derived from the
    /// sender's bytes.
    pub(crate) reason: &'static str,
    /// The SELF-REPORTED signer id, sanitised (see [`sanitize_worker_id`]).
    /// Unverified by definition — this log line exists precisely because the
    /// claim did not check out — so it is bounded and charset-filtered before
    /// it reaches the log.
    pub(crate) worker_id: String,
    /// One sentence an operator can act on, or an explicit "not applicable".
    pub(crate) skew_hint: String,
}

/// Placeholder for classes where build skew is not a plausible explanation.
/// Spelled out rather than omitted so a log reader never has to wonder
/// whether the hint was computed and came back empty.
const HINT_NOT_APPLICABLE: &str = "n/a — not a build-skew class";

/// Bound and charset-filter the self-reported `worker_id` before logging it.
///
/// It is the one attacker-influenceable string in the new log fields (the
/// signature that would have vouched for it is the thing that just failed),
/// so it gets the same treatment the registration endpoint gives it:
/// `[A-Za-z0-9._-]` only, truncated. An empty or fully-filtered value renders
/// as `none`, which is also the honest rendering for a legacy-HMAC request
/// (that scheme carries no worker id at all).
fn sanitize_worker_id(worker_id: &str) -> String {
    const MAX: usize = 64;
    let cleaned: String = worker_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(MAX)
        .collect();
    if cleaned.is_empty() {
        "none".to_string()
    } else {
        cleaned
    }
}

/// Assemble the rejection-log fields for one refused request.
///
/// Takes the request through [`AdmittableRpc`] rather than a bare `&str` so
/// every protocol reads its signer id from the ONE declared accessor — a new
/// subscriber cannot quietly log a different field (or forget the id) and
/// still compile against this helper.
pub(crate) fn reject_diagnostics<T: AdmittableRpc>(
    reason: RejectReason,
    req: &T,
) -> RejectDiagnostics {
    let worker_id = sanitize_worker_id(req.worker_id());
    RejectDiagnostics {
        reason: reason.as_str(),
        skew_hint: if reason.is_skew_candidate() {
            crate::build_skew::skew_hint(&worker_id)
        } else {
            HINT_NOT_APPLICABLE.to_string()
        },
        worker_id,
    }
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
    // Short-circuit order preserved verbatim: per-protocol verify first (its
    // own cheap gates run before its crypto), and the cross-replica guard —
    // which costs a shared-store round trip — only for a request that already
    // verified. The two failures land in the SAME `Unauthorized` arm as
    // before; only the log-side classification is new.
    if let Err(failure) = req.verify_classified() {
        return Err(AdmitError::Unauthorized {
            reason: RejectReason::Verify(failure),
        });
    }
    if !crate::crossreplica_replay_ok(T::WIRE_SUBJECT, req.actor_id(), req.nonce()).await {
        return Err(AdmitError::Unauthorized {
            reason: RejectReason::CrossReplicaReplay,
        });
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

    use talos_memory::rpc_auth::VerifyFailure;

    // A minimal in-crate protocol standing in for the real ones, so the
    // gate's ordering and fail-closed arms are pinned without NATS or a
    // registered HMAC key.
    //
    // `failure_index` selects which classification the stand-in `verify()`
    // reports (`None` = admit), carried as an INDEX rather than the enum
    // itself: `VerifyFailure` deliberately implements neither `Serialize` nor
    // `Deserialize`, which is a small structural guarantee that it cannot be
    // dropped into a wire reply by accident. Keeping the test harness honest
    // to that is worth one lookup table.
    const FAILURE_CLASSES: [VerifyFailure; 5] = [
        VerifyFailure::Stale,
        VerifyFailure::NonFinite,
        VerifyFailure::OversizedStructure,
        VerifyFailure::UnknownSignerKey,
        VerifyFailure::BadSignature,
    ];

    #[derive(serde::Serialize, serde::Deserialize)]
    struct FakeReq {
        actor_id: uuid::Uuid,
        nonce: String,
        failure_index: Option<usize>,
        #[serde(default)]
        worker_id: String,
    }

    impl FakeReq {
        fn admitting() -> Self {
            Self {
                actor_id: uuid::Uuid::new_v4(),
                nonce: canonical_nonce(),
                failure_index: None,
                worker_id: "fake-worker".to_string(),
            }
        }
        fn failing(failure: VerifyFailure) -> Self {
            let failure_index = FAILURE_CLASSES.iter().position(|f| *f == failure);
            assert!(failure_index.is_some(), "unmapped VerifyFailure variant");
            Self {
                failure_index,
                ..Self::admitting()
            }
        }
    }

    impl AdmittableRpc for FakeReq {
        const WIRE_SUBJECT: &'static str = "talos.test.admission";
        const SIGNING_SUBJECT: &'static str = "admission_test_rpc";
        fn verify_classified(&self) -> Result<(), VerifyFailure> {
            match self.failure_index {
                Some(i) => Err(FAILURE_CLASSES[i]),
                None => Ok(()),
            }
        }
        fn actor_id(&self) -> uuid::Uuid {
            self.actor_id
        }
        fn nonce(&self) -> &str {
            &self.nonce
        }
        fn worker_id(&self) -> &str {
            &self.worker_id
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
        let req = FakeReq::failing(VerifyFailure::BadSignature);
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let err = admit_from_bytes::<FakeReq>(&bytes).await;
        assert!(matches!(err, Err(AdmitError::Unauthorized { .. })));
    }

    /// EVERY verify class lands in the SAME `Unauthorized` arm — the collapse
    /// is unchanged — while the carried `reason` faithfully reports which
    /// gate fired. Both halves matter: the first is the anti-oracle property,
    /// the second is the whole point of the change.
    #[tokio::test]
    async fn every_verify_class_is_unauthorized_and_reports_itself() {
        for class in FAILURE_CLASSES {
            let bytes = serde_json::to_vec(&FakeReq::failing(class)).expect("serialize");
            match admit_from_bytes::<FakeReq>(&bytes).await {
                Err(AdmitError::Unauthorized { reason }) => {
                    assert_eq!(reason, RejectReason::Verify(class));
                    assert_eq!(reason.as_str(), class.as_str());
                }
                _ => panic!("{class} must admit-fail as Unauthorized"),
            }
        }
    }

    /// The skew hint is attached to `bad_signature` and nothing else.
    #[test]
    fn only_bad_signature_is_a_skew_candidate() {
        for class in FAILURE_CLASSES {
            assert_eq!(
                RejectReason::Verify(class).is_skew_candidate(),
                class == VerifyFailure::BadSignature,
                "{class} skew-candidacy is wrong"
            );
        }
        assert!(!RejectReason::CrossReplicaReplay.is_skew_candidate());
        assert_eq!(
            RejectReason::CrossReplicaReplay.as_str(),
            "cross_replica_replay"
        );
    }

    #[tokio::test]
    async fn admitted_once_then_replay_rejected() {
        let req = FakeReq::admitting();
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
        let forged = FakeReq::failing(VerifyFailure::BadSignature);
        let (actor, nonce) = (forged.actor_id, forged.nonce.clone());
        let bytes = serde_json::to_vec(&forged).expect("serialize");
        assert!(matches!(
            admit_from_bytes::<FakeReq>(&bytes).await,
            Err(AdmitError::Unauthorized { .. })
        ));
        let genuine = FakeReq {
            actor_id: actor,
            nonce,
            ..FakeReq::admitting()
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
        let req = FakeReq::admitting();
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let admitted = admit_from_bytes::<FakeReq>(&bytes)
            .await
            .ok()
            .expect("admitted");
        assert_eq!(admitted.actor_id(), req.actor_id); // Deref
        assert_eq!(admitted.worker_id(), req.worker_id); // Deref
        let owned = admitted.into_inner();
        assert_eq!(owned.nonce, req.nonce);
    }

    /// ORDERING pin. `Malformed` must win over verification (an unparseable
    /// payload never reaches `verify()`), and the process-local nonce record
    /// must come strictly AFTER verification and the cross-replica guard —
    /// otherwise a forged message could burn a legitimate sender's nonce.
    /// The second half is covered by
    /// `rejected_verification_does_not_burn_the_nonce`; this pins the first
    /// half plus the reason a malformed payload carries (parse text, which
    /// describes the caller's OWN bytes — the one thing that legitimately
    /// goes back on the wire).
    #[tokio::test]
    async fn parse_precedes_verification() {
        // Well-formed JSON, wrong shape: still Malformed, and no classified
        // reason is produced because `verify()` never ran.
        let err = admit_from_bytes::<FakeReq>(br#"{"actor_id":"not-a-uuid"}"#).await;
        assert!(matches!(err, Err(AdmitError::Malformed(_))));
    }
}
