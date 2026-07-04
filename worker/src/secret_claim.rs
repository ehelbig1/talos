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
    ClaimResponse, DispatchSigningKey, DispatchVerifyingKey, SecretClaim, WorkerEphemeral,
};
use uuid::Uuid;

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

/// Generate the ephemeral keypair and build the signed `SecretClaim` for an
/// execution. `exec_id` is the id the controller registered the seal context
/// under (the dispatch `job_id` for both single-node and pipeline jobs). Returns
/// the ephemeral (to open the reply with) and the serialized claim payload. Pure
/// except for the ephemeral RNG.
pub fn build_claim(
    exec_id: Uuid,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
) -> Result<(WorkerEphemeral, Vec<u8>), ClaimClientError> {
    let we = WorkerEphemeral::generate();
    let claim = SecretClaim::new_signed(
        exec_id,
        worker_id.to_string(),
        we.public_key(),
        worker_signing_key,
    );
    let payload = serde_json::to_vec(&claim).map_err(|e| ClaimClientError::Serde(e.to_string()))?;
    Ok((we, payload))
}

/// Verify + open the controller's reply, returning the RAW opened plaintext
/// bytes. Consumes the ephemeral (single-use → forward secrecy). The caller
/// deserializes the bytes into whatever shape it sealed — a flat
/// `HashMap<String,String>` (single-node) or a per-step
/// `Vec<HashMap<String,String>>` (pipeline). Pure and testable.
pub fn process_reply_raw(
    we: WorkerEphemeral,
    exec_id: Uuid,
    worker_id: &str,
    controller_keys: &[DispatchVerifyingKey],
    reply_bytes: &[u8],
) -> Result<Vec<u8>, ClaimClientError> {
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
    we.open(
        &sealed.epk_c,
        exec_id,
        worker_id,
        &sealed.ciphertext,
        &sealed.nonce,
    )
    .map_err(ClaimClientError::OpenFailed)
}

/// Verify + open the controller's reply into a flat secrets map (single-node
/// convenience over [`process_reply_raw`]).
pub fn process_reply(
    we: WorkerEphemeral,
    exec_id: Uuid,
    worker_id: &str,
    controller_keys: &[DispatchVerifyingKey],
    reply_bytes: &[u8],
) -> Result<HashMap<String, String>, ClaimClientError> {
    let plaintext = process_reply_raw(we, exec_id, worker_id, controller_keys, reply_bytes)?;
    serde_json::from_slice(&plaintext).map_err(|e| ClaimClientError::Serde(e.to_string()))
}

/// Full claim round-trip over NATS returning the RAW opened plaintext bytes.
/// `claim_inbox` is the subject the dispatch named (`None` ⇒ malformed dispatch).
/// The caller deserializes the bytes into the shape it expects (flat map for a
/// single node, per-step vector for a pipeline).
pub async fn claim_secrets_raw(
    nc: &async_nats::Client,
    exec_id: Uuid,
    claim_inbox: Option<&str>,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
    controller_keys: &[DispatchVerifyingKey],
) -> Result<Vec<u8>, ClaimClientError> {
    let claim_inbox = claim_inbox.ok_or(ClaimClientError::MissingClaimInbox)?;
    if controller_keys.is_empty() {
        return Err(ClaimClientError::NoControllerKey);
    }

    let (we, payload) = build_claim(exec_id, worker_id, worker_signing_key)?;

    let reply = tokio::time::timeout(
        CLAIM_TIMEOUT,
        nc.request(claim_inbox.to_string(), payload.into()),
    )
    .await
    .map_err(|_| ClaimClientError::Transport("claim request timed out".to_string()))?
    .map_err(|e| ClaimClientError::Transport(e.to_string()))?;

    process_reply_raw(we, exec_id, worker_id, controller_keys, &reply.payload)
}

/// Full claim round-trip over NATS returning a flat secrets map (single-node
/// convenience over [`claim_secrets_raw`]).
pub async fn claim_secrets(
    nc: &async_nats::Client,
    exec_id: Uuid,
    claim_inbox: Option<&str>,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
    controller_keys: &[DispatchVerifyingKey],
) -> Result<HashMap<String, String>, ClaimClientError> {
    let plaintext = claim_secrets_raw(
        nc,
        exec_id,
        claim_inbox,
        worker_id,
        worker_signing_key,
        controller_keys,
    )
    .await?;
    serde_json::from_slice(&plaintext).map_err(|e| ClaimClientError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::{seal_secrets, SealedSecrets};

    #[test]
    fn build_and_process_roundtrip_against_simulated_controller() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = controller_sk.verifying_key();
        let job_id = uuid::Uuid::new_v4();

        // Worker builds the claim.
        let (we, claim_payload) = build_claim(job_id, "worker-7", &worker_sk).unwrap();
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
        let map = process_reply(we, job_id, "worker-7", &[controller_vk], &reply).unwrap();
        assert_eq!(map.get("anthropic/api_key").unwrap(), "sk-ant-x");
    }

    #[test]
    fn rejected_reply_fails_closed() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let controller_vk = DispatchSigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let (we, _payload) = build_claim(job_id, "w", &worker_sk).unwrap();
        let reply = serde_json::to_vec(&ClaimResponse::Rejected {
            reason: "unknown execution".to_string(),
        })
        .unwrap();
        let err = process_reply(we, job_id, "w", &[controller_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::Rejected(_)));
    }

    #[test]
    fn wrong_controller_key_fails_verify() {
        let worker_sk = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let real_controller = DispatchSigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_vk = DispatchSigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let (we, claim_payload) = build_claim(job_id, "w", &worker_sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&claim_payload).unwrap();
        let out = seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, b"{}").unwrap();
        let sealed = SealedSecrets::new_signed(claim.exec_id, out, &real_controller);
        let reply = serde_json::to_vec(&ClaimResponse::Sealed(sealed)).unwrap();
        // Worker only trusts `wrong_vk` → verify fails.
        let err = process_reply(we, job_id, "w", &[wrong_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::VerifyFailed));
    }
}
