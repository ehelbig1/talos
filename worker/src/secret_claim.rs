//! RFC 0010 P3 (D3b) — worker-side secret claim client.
//!
//! When a dispatch arrives with `sealing == SEALING_CLAIM_ECIES`, the worker
//! does NOT find its secrets inline in `encrypted_secrets`. Instead it:
//!   1. generates a fresh per-execution ephemeral X25519 keypair,
//!   2. sends a `SecretClaim` (Ed25519-signed by its long-term registered key,
//!      binding the ephemeral public key) to the dispatch's `claim_inbox`,
//!   3. verifies the controller-signed `SealedSecrets` reply and opens it with
//!      the ephemeral secret (consumed → forward secrecy),
//!   4. loads the resulting plaintext secrets map into the `SecretProvider`.
//!
//! The crypto handshake is split into pure `build_claim` / `process_reply`
//! functions (unit-testable without a broker) and a thin `claim_secrets` NATS
//! wrapper.

use std::collections::HashMap;
use std::time::Duration;

use talos_workflow_job_protocol::{
    ClaimResponse, DispatchSigningKey, DispatchVerifyingKey, JobRequest, SecretClaim,
    WorkerEphemeral,
};

/// How long the worker waits for the controller's `SealedSecrets` reply before
/// giving up (and failing the job). The claim is an in-cluster request/reply;
/// the controller seals synchronously, so this is generous.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

/// Freshness window (seconds) the worker allows on the controller's
/// `SealedSecrets` — matches the dispatch-verify window elsewhere.
const SEALED_MAX_AGE_SECS: u64 = 300;

/// Everything that can go wrong obtaining sealed secrets. All map to "fail the
/// job" — a job whose secrets can't be obtained cannot run (fail-closed, never
/// run secretless).
#[derive(Debug)]
pub enum ClaimClientError {
    /// `sealing == 1` but the dispatch carried no `claim_inbox` (malformed).
    MissingClaimInbox,
    /// No controller public key configured — cannot verify the reply.
    NoControllerKey,
    /// NATS request failed or timed out.
    Transport(String),
    /// The controller rejected the claim (unknown/already-claimed execution,
    /// unauthorized, seal failure). The worker drops the job without running.
    Rejected(String),
    /// The reply's controller signature did not verify.
    VerifyFailed,
    /// ECDH/AEAD open failed (wrong key or tampered ciphertext).
    OpenFailed(String),
    /// (De)serialization of the claim or reply failed.
    Serde(String),
}

impl std::fmt::Display for ClaimClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClaimInbox => write!(f, "dispatch has sealing=1 but no claim_inbox"),
            Self::NoControllerKey => write!(f, "no controller public key configured"),
            Self::Transport(e) => write!(f, "claim transport error: {e}"),
            Self::Rejected(r) => write!(f, "claim rejected by controller: {r}"),
            Self::VerifyFailed => write!(f, "SealedSecrets signature did not verify"),
            Self::OpenFailed(e) => write!(f, "failed to open sealed secrets: {e}"),
            Self::Serde(e) => write!(f, "claim (de)serialization error: {e}"),
        }
    }
}

impl std::error::Error for ClaimClientError {}

/// Generate the ephemeral keypair and build the signed `SecretClaim` for a
/// dispatch. Returns the ephemeral (to open the reply with) and the serialized
/// claim payload. Pure except for the ephemeral RNG.
pub fn build_claim(
    req: &JobRequest,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
) -> Result<(WorkerEphemeral, Vec<u8>), ClaimClientError> {
    let we = WorkerEphemeral::generate();
    // exec_id = job_id (unique per dispatch); the controller registered the seal
    // context under this same id.
    let claim = SecretClaim::new_signed(
        req.job_id,
        worker_id.to_string(),
        we.public_key(),
        worker_signing_key,
    );
    let payload = serde_json::to_vec(&claim).map_err(|e| ClaimClientError::Serde(e.to_string()))?;
    Ok((we, payload))
}

/// Verify + open the controller's reply, returning the plaintext secrets map.
/// Consumes the ephemeral (single-use → forward secrecy). Pure and testable.
pub fn process_reply(
    we: WorkerEphemeral,
    req: &JobRequest,
    worker_id: &str,
    controller_keys: &[DispatchVerifyingKey],
    reply_bytes: &[u8],
) -> Result<HashMap<String, String>, ClaimClientError> {
    if controller_keys.is_empty() {
        return Err(ClaimClientError::NoControllerKey);
    }
    let resp: ClaimResponse =
        serde_json::from_slice(reply_bytes).map_err(|e| ClaimClientError::Serde(e.to_string()))?;
    let sealed = match resp {
        ClaimResponse::Sealed(s) => s,
        ClaimResponse::Rejected { reason } => return Err(ClaimClientError::Rejected(reason)),
    };
    // The reply must be signed by a currently-trusted controller key (current or
    // rotated-out overlap key).
    if !controller_keys
        .iter()
        .any(|vk| sealed.verify(vk, SEALED_MAX_AGE_SECS).is_ok())
    {
        return Err(ClaimClientError::VerifyFailed);
    }
    let plaintext = we
        .open(
            &sealed.epk_c,
            req.job_id,
            worker_id,
            &sealed.ciphertext,
            &sealed.nonce,
        )
        .map_err(ClaimClientError::OpenFailed)?;
    serde_json::from_slice(&plaintext).map_err(|e| ClaimClientError::Serde(e.to_string()))
}

/// Full claim round-trip over NATS: build the claim, request it on the
/// dispatch's `claim_inbox`, and verify+open the reply. Returns the plaintext
/// secrets map to load into the `SecretProvider`.
pub async fn claim_secrets(
    nc: &async_nats::Client,
    req: &JobRequest,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
    controller_keys: &[DispatchVerifyingKey],
) -> Result<HashMap<String, String>, ClaimClientError> {
    let claim_inbox = req
        .claim_inbox
        .as_deref()
        .ok_or(ClaimClientError::MissingClaimInbox)?;
    if controller_keys.is_empty() {
        return Err(ClaimClientError::NoControllerKey);
    }

    let (we, payload) = build_claim(req, worker_id, worker_signing_key)?;

    let reply = tokio::time::timeout(
        CLAIM_TIMEOUT,
        nc.request(claim_inbox.to_string(), payload.into()),
    )
    .await
    .map_err(|_| ClaimClientError::Transport("claim request timed out".to_string()))?
    .map_err(|e| ClaimClientError::Transport(e.to_string()))?;

    process_reply(we, req, worker_id, controller_keys, &reply.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::{seal_secrets, SealedSecrets};

    // A JobRequest with the fields the claim path reads; the rest are defaults
    // that don't affect the crypto.
    fn dispatch(job_id: uuid::Uuid) -> JobRequest {
        let mut req: JobRequest = serde_json::from_value(serde_json::json!({
            "job_id": job_id,
            "workflow_execution_id": uuid::Uuid::new_v4(),
            "module_uri": "redis:wasm:x",
            "input_payload": {},
            "timeout_ms": 1000,
            "allowed_hosts": [],
            "signature": [],
            "job_nonce": "0:00",
        }))
        .expect("construct JobRequest");
        req.sealing = talos_workflow_job_protocol::SEALING_CLAIM_ECIES;
        req.claim_inbox = Some("talos.claims.replica-1".to_string());
        req
    }

    #[test]
    fn build_and_process_roundtrip_against_simulated_controller() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = controller_sk.verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let req = dispatch(job_id);

        // Worker builds the claim.
        let (we, claim_payload) = build_claim(&req, "worker-7", &worker_sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&claim_payload).unwrap();
        assert_eq!(claim.exec_id, job_id);

        // Simulate the controller: seal the secrets to the claim's epk_w.
        let secrets: HashMap<String, String> =
            [("anthropic/api_key".to_string(), "sk-ant-x".to_string())]
                .into_iter()
                .collect();
        let secrets_json = serde_json::to_vec(&secrets).unwrap();
        let out =
            seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, &secrets_json).unwrap();
        let sealed = SealedSecrets::new_signed(claim.exec_id, out, &controller_sk);
        let reply = serde_json::to_vec(&ClaimResponse::Sealed(sealed)).unwrap();

        // Worker opens the reply.
        let map = process_reply(we, &req, "worker-7", &[controller_vk], &reply).unwrap();
        assert_eq!(map.get("anthropic/api_key").unwrap(), "sk-ant-x");
    }

    #[test]
    fn rejected_reply_fails_closed() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = DispatchSigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let req = dispatch(uuid::Uuid::new_v4());
        let (we, _payload) = build_claim(&req, "w", &worker_sk).unwrap();
        let reply = serde_json::to_vec(&ClaimResponse::Rejected {
            reason: "unknown execution".to_string(),
        })
        .unwrap();
        let err = process_reply(we, &req, "w", &[controller_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::Rejected(_)));
    }

    #[test]
    fn wrong_controller_key_fails_verify() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let real_controller = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_vk = DispatchSigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let req = dispatch(job_id);
        let (we, claim_payload) = build_claim(&req, "w", &worker_sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&claim_payload).unwrap();
        let out = seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, b"{}").unwrap();
        let sealed = SealedSecrets::new_signed(claim.exec_id, out, &real_controller);
        let reply = serde_json::to_vec(&ClaimResponse::Sealed(sealed)).unwrap();
        // Worker only trusts `wrong_vk` → verify fails.
        let err = process_reply(we, &req, "w", &[wrong_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::VerifyFailed));
    }
}
