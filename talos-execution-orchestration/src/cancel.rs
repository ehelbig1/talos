//! Operator-initiated execution cancellation: the DB mark and the fleet
//! broadcast, in one place so they cannot be called out of order.
//!
//! # Why both halves live in one function
//!
//! The tenancy rule for the cancel command is *"publish only when
//! `mark_execution_cancelled(exec_id, user_id)` returned `Ok(true)`"* — the
//! worker is credential-free and cannot evaluate ownership, so the UPDATE's
//! `WHERE ... AND user_id = $2` is the entire authorization check. Splitting
//! the mark from the publish would make that rule a comment on a public
//! method, i.e. exactly the "enforced at one end, unpopulated at the other"
//! shape this work exists to close. Here it is structural: there is one entry
//! point, and the publish is unreachable unless the UPDATE matched a row the
//! caller owns.

use std::sync::Arc;

use talos_workflow_job_protocol::{subjects, CancelCommand, DispatchSigner};
use uuid::Uuid;

use crate::{ExecutionOrchestrationService, OrchestrationError};

/// What actually happened to the fleet broadcast, so the protocol layer can
/// report it instead of asserting it.
///
/// This exists because of the field it replaces. `cancel_execution` used to
/// return a flat `"in_flight_node_aborted": false`, which was true when
/// written and becomes the next misleading field the moment a producer lands.
/// A boolean cannot distinguish "no worker held it" from "we could not sign",
/// and those call for opposite operator responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelBroadcast {
    /// The row was not marked (wrong status, or not the caller's), so nothing
    /// was published. Publishing here would be an unauthenticated abort.
    NotAttempted,
    /// Signed and published to the fleet. **This does not assert that any
    /// worker was holding an in-flight job** — the controller cannot know
    /// that; the command is a plain broadcast and workers that do not hold the
    /// execution no-op. It asserts delivery to the bus, nothing more.
    Published,
    /// No NATS client configured (unit tests, dev embeddings). The row is
    /// marked; nothing can reach a worker.
    NoNatsClient,
    /// Neither an Ed25519 dispatch key nor a `WORKER_SHARED_KEY` is available,
    /// so no command could be signed. An UNSIGNED command is deliberately not
    /// sent: every worker would refuse it, and publishing one would report a
    /// success that cannot happen.
    NoSigningKey,
    /// Signing or publishing failed. Carries a short, non-sensitive reason.
    Failed(String),
}

impl CancelBroadcast {
    /// A stable machine-readable tag for the MCP/GraphQL response.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Published => "published",
            Self::NoNatsClient => "no_nats_client",
            Self::NoSigningKey => "no_signing_key",
            Self::Failed(_) => "failed",
        }
    }

    /// `true` only when a signed command actually reached the bus.
    #[must_use]
    pub fn reached_the_fleet(&self) -> bool {
        matches!(self, Self::Published)
    }
}

/// Result of [`ExecutionOrchestrationService::cancel_execution`].
#[derive(Debug, Clone)]
pub struct CancelOutcome {
    /// Whether the `workflow_executions` row moved to `cancelled`. `false`
    /// means the row was absent, already terminal, or not the caller's — the
    /// three are indistinguishable here by design (tenant isolation); the
    /// protocol layer does a follow-up read to render an actionable message.
    pub marked: bool,
    /// What happened to the fleet broadcast.
    pub broadcast: CancelBroadcast,
}

impl ExecutionOrchestrationService {
    /// Mark an execution cancelled and, only if that succeeded, broadcast a
    /// signed [`CancelCommand`] to the worker fleet.
    ///
    /// # What the broadcast does and does not buy
    ///
    /// A worker holding an in-flight job for this execution sets that job's
    /// cancellation flag, which the in-worker egress guards read: the next
    /// off-host call the module attempts fails with `reason_class=cancelled`,
    /// which both transient classifiers treat as NON-transient, so it is not
    /// re-dispatched. A module that makes no host calls at all is no longer
    /// exempt either: the worker's per-Store epoch-deadline callback
    /// (`talos_worker_runtime::epoch_budget`) re-reads the same flag roughly
    /// every 100 ms of guest execution and traps the module out of its own
    /// computation, so a compute-bound module no longer runs to its timeout.
    ///
    /// What is still NOT bought, and must not be claimed — this is the defect
    /// #687 fixed and it has not gone away: the broadcast is fire-and-forget
    /// with no reply, so the abort is REQUESTED, never confirmed, and nothing
    /// here reaches a worker that did not receive the command.
    ///
    /// Audit is not bypassed: the job fails through the ordinary path, so the
    /// `node_failed` row and the DLQ entry are still written.
    pub async fn cancel_execution(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
    ) -> Result<CancelOutcome, OrchestrationError> {
        // AUTHORIZATION. The UPDATE matches on `user_id`, so a caller who does
        // not own the execution updates zero rows and nothing is published.
        let marked = self
            .execution_repo
            .mark_execution_cancelled(exec_id, user_id)
            .await
            .map_err(OrchestrationError::Internal)?;

        if !marked {
            return Ok(CancelOutcome {
                marked: false,
                broadcast: CancelBroadcast::NotAttempted,
            });
        }

        Ok(CancelOutcome {
            marked: true,
            broadcast: self.broadcast_cancel(exec_id).await,
        })
    }

    /// Sign and publish the fleet-wide cancel. Private: the only caller is
    /// [`Self::cancel_execution`], which has already established ownership.
    async fn broadcast_cancel(&self, exec_id: Uuid) -> CancelBroadcast {
        let Some(nats) = self.nats_client.as_ref() else {
            return CancelBroadcast::NoNatsClient;
        };

        // Same scheme as job dispatch, resolved from the same process-wide
        // source of truth. An HMAC-only cancel would be refused outright by a
        // fleet running `TALOS_DISPATCH_REQUIRE_ED25519`.
        let signer = match talos_workflow_job_protocol::configured_dispatch_signer() {
            Some(s) => s,
            None => match self.worker_shared_key.as_ref() {
                Some(k) => DispatchSigner::Hmac(Arc::new(k.as_bytes().to_vec())),
                None => return CancelBroadcast::NoSigningKey,
            },
        };

        let mut cmd = CancelCommand::new(exec_id);
        if let Err(e) = signer.sign_cancel(&mut cmd) {
            // The message is a protocol/key-shape diagnostic, never key bytes.
            tracing::error!(error = %e, "failed to sign the execution cancel command");
            return CancelBroadcast::Failed("could not sign the cancel command".to_string());
        }

        let bytes = match serde_json::to_vec(&cmd) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "failed to encode the execution cancel command");
                return CancelBroadcast::Failed("could not encode the cancel command".to_string());
            }
        };

        // The subject is a fleet-wide constant: the execution id travels in the
        // signed BODY, never in the subject, which is world-readable via NATS
        // `/subsz`.
        if let Err(e) = nats
            .publish(subjects::WORKERS_CMD_CANCEL, bytes.into())
            .await
        {
            tracing::error!(error = %e, "failed to publish the execution cancel command");
            return CancelBroadcast::Failed("could not reach the message bus".to_string());
        }

        // Flush before reporting `Published`. `publish` only buffers, so
        // without this the response would claim delivery the process had not
        // yet performed — the same class of claim-ahead-of-fact this whole
        // change exists to remove.
        if let Err(e) = nats.flush().await {
            tracing::error!(error = %e, "failed to flush the execution cancel command");
            return CancelBroadcast::Failed("could not reach the message bus".to_string());
        }

        CancelBroadcast::Published
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_tags_are_stable_and_distinct() {
        // Downstream renders these verbatim; a rename is a protocol change.
        let all = [
            CancelBroadcast::NotAttempted,
            CancelBroadcast::Published,
            CancelBroadcast::NoNatsClient,
            CancelBroadcast::NoSigningKey,
            CancelBroadcast::Failed("x".into()),
        ];
        let tags: Vec<_> = all.iter().map(CancelBroadcast::as_str).collect();
        assert_eq!(
            tags,
            [
                "not_attempted",
                "published",
                "no_nats_client",
                "no_signing_key",
                "failed"
            ]
        );
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len(), "tags must be distinct");
    }

    /// The whole reason this enum replaced a boolean: only ONE of the five
    /// outcomes means a signed command reached the bus, and the four that do
    /// not are not interchangeable.
    #[test]
    fn only_published_counts_as_reaching_the_fleet() {
        assert!(CancelBroadcast::Published.reached_the_fleet());
        for other in [
            CancelBroadcast::NotAttempted,
            CancelBroadcast::NoNatsClient,
            CancelBroadcast::NoSigningKey,
            CancelBroadcast::Failed("bus down".into()),
        ] {
            assert!(
                !other.reached_the_fleet(),
                "{} must not read as delivered",
                other.as_str()
            );
        }
    }
}
