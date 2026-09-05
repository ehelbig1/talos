//! Controller-side write-ceiling gate for the signed-RPC mutation routes.
//!
//! # Why this exists
//!
//! `actors.max_write_ceiling` is ONE control. #750 established that it must be
//! checked on EVERY route to a mutation rather than on the routes that
//! happened to be built first; it closed the controller's `__memory_write__`
//! envelope route and RECORDED, without fixing, the next one — "the
//! memory-RPC `MemoryOp::Set` handler (`talos-rpc-subscribers`) still TRUSTS
//! the worker's gate".
//!
//! That trust rests on an assumption the transport does not support. The
//! request is HMAC-signed under `WORKER_SHARED_KEY`, which is **fleet-shared**
//! (`rpc_auth`'s own module docs say a compromised worker leaking it "can
//! forge requests for ANY actor"). So the signature proves the sender holds
//! the fleet key — it does not prove the sender ran a write-ceiling gate. Three
//! realistic senders do not:
//!
//! * a worker booted without `TALOS_WRITE_CEILING_ENFORCED`, which is exactly
//!   the mixed-fleet state `get_platform_info.fleet.write_ceiling.enforced_by
//!   = "some"` reports and #752 calls "the dangerous one";
//! * a worker running an older build, from before the gate existed;
//! * any process at all that has the key.
//!
//! Measured on pristine `main` (2026-09-05,
//! `controller/tests/rpc_write_ceiling_tests.rs`): with enforcement ON at the
//! controller, a signed `MemoryOp::Set` naming an actor whose
//! `max_write_ceiling = 'readonly'` landed a row in `actor_memory` and the
//! reply said `Ok`.
//!
//! # Shape
//!
//! [`decide`] is **pure** — `enforced` is a parameter, not an env read, and
//! the database answer arrives as a three-valued [`CeilingRead`] — so the rule
//! is testable with no process env and no Postgres, and so the two states that
//! mean *unknown* cannot be collapsed into the state that means *permitted*.
//! The DECISION itself is [`talos_workflow_job_protocol::write_ceiling_denies`]
//! (a re-export of `talos_workflow_engine_core`'s), shared with the worker and
//! with #750's envelope gate rather than re-derived here: two paths answering
//! one question differently IS the defect.
//!
//! # What this deliberately does NOT do
//!
//! It does not read the env itself. [`gate`] calls
//! `talos_workflow_engine::write_ceiling_gate::controller_write_ceiling_enforced`
//! — the controller process's ONE reader of `TALOS_WRITE_CEILING_ENFORCED`,
//! already cached in a `OnceLock` and already consulted by the envelope gate.
//! A second reader here would be a second answer to "is this control live",
//! which is check 69's class.
//!
//! It does not gate `talos.state.write`. See [`CONTROLLER_SERVED_WRITE_OPS`].

use talos_workflow_engine_core::{write_ceiling_denies, WriteCeiling};

/// The answer to "what is this actor's ceiling?", kept three-valued so a
/// caller must say what an unreadable answer means at its own site.
///
/// Same shape and same reasoning as `ExecutionLookup` (#748) and
/// `classify_input_schema_read` (#730): a determinate value, a determinate
/// absence, and *we could not look* are three different facts, and folding the
/// third into either of the others is how a gate silently stops gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeilingRead {
    /// The row was read and carried a (fail-closed parsed) ceiling.
    Found(WriteCeiling),
    /// No `actors` row with this id. Reachable legitimately — an actor
    /// deleted while one of its jobs was still in flight — and illegitimately,
    /// since the caller supplies the id under a FLEET-SHARED signature.
    NoSuchActor,
    /// The lookup itself failed (pool exhaustion, Postgres restart, column
    /// drift). Carries no detail: nothing downstream may act on the cause,
    /// and the raw error must not reach a caller.
    Unreadable,
}

/// Why a mutation was refused. **Operator-facing only** — see
/// [`CeilingDecision`] for why this does not reach the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    /// The actor exists, enforcement is on, and its ceiling is `readonly`.
    Policy,
    /// The rule could not be read (absent actor, or a failed lookup), so the
    /// gate failed CLOSED. Distinct from [`Self::Policy`] because it names an
    /// operator problem — a dangling actor id, or a database the enforcement
    /// path cannot reach — rather than a policy working as configured.
    Unreadable,
}

impl RefusalReason {
    /// Stable snake_case token for logs and the `talos_rpc` outcome tag.
    /// Append, never rename — dashboards key on these.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "write_ceiling",
            Self::Unreadable => "write_ceiling_unreadable",
        }
    }

    /// The same two-valued fact, spelled for the `reason` label of
    /// `talos_rpc_write_ceiling_refusals_total`.
    ///
    /// A SECOND spelling of one fact is the drift this file's own tests are
    /// about, so it is justified rather than assumed: the metric is already
    /// named `..._write_ceiling_refusals_total`, so a label reading
    /// `reason="write_ceiling"` says the metric's own name back and carries no
    /// information, while `reason="write_ceiling_unreadable"` is the only value
    /// that distinguishes anything. The short pair is what a dashboard legend
    /// can render. `refusal_reason_spellings_stay_paired` pins the mapping, and
    /// the `match` is exhaustive, so a third variant cannot be added without
    /// deciding its metric spelling.
    ///
    /// The LOG keeps [`Self::as_str`] — those tokens are the worker's, and
    /// renaming them would break the `mutation_profile` ↔ audit-event
    /// correlation `get_module_info` promises.
    pub(crate) fn metric_label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Unreadable => "unreadable",
        }
    }
}

/// The gate's verdict.
///
/// `#[must_use]`: a gate whose answer is computed and dropped is worse than no
/// gate, because the code then LOOKS gated. (#736's shape — a classifier that
/// runs and whose result is thrown away — was measured as the survivor of
/// every other instrument in that change.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum CeilingDecision {
    Permit,
    Refuse(RefusalReason),
}

impl CeilingDecision {
    pub(crate) fn is_refused(self) -> bool {
        matches!(self, Self::Refuse(_))
    }
}

/// The rule, with nothing else in it.
///
/// * Enforcement off (the staged-rollout default) ⇒ `Permit`, unconditionally
///   and without consulting the read at all. This is byte-identical to
///   pre-change behaviour and is why the async wrapper never touches the
///   database on a default-configured deployment.
/// * Enforcement on ⇒ the shared `write_ceiling_denies` decides for a ceiling
///   that was actually read; every other read outcome refuses.
///
/// **Fail closed is not a preference here, it is the only defensible answer.**
/// A gate that cannot read its rule and PERMITS has, in the moment that
/// matters most (a database incident), exactly the behaviour of no gate — and
/// unlike no gate, it leaves logs implying one ran.
pub(crate) fn decide(enforced: bool, read: CeilingRead) -> CeilingDecision {
    if !enforced {
        return CeilingDecision::Permit;
    }
    match read {
        CeilingRead::Found(ceiling) => {
            if write_ceiling_denies(true, ceiling) {
                CeilingDecision::Refuse(RefusalReason::Policy)
            } else {
                CeilingDecision::Permit
            }
        }
        CeilingRead::NoSuchActor | CeilingRead::Unreadable => {
            CeilingDecision::Refuse(RefusalReason::Unreadable)
        }
    }
}

/// Read the actor's ceiling and CLASSIFY the read.
///
/// The `Err` arm is logged here (with the full chain, controller-side only)
/// and collapsed to [`CeilingRead::Unreadable`]: the cause is an operator
/// concern and must never travel to a caller, per the checklist's §3 rule that
/// raw Postgres text leaks schema.
async fn read_ceiling(pool: &sqlx::PgPool, actor_id: uuid::Uuid) -> CeilingRead {
    match talos_actor_repository::read_actor_write_ceiling(pool, actor_id).await {
        Ok(Some(c)) => CeilingRead::Found(c),
        Ok(None) => CeilingRead::NoSuchActor,
        Err(e) => {
            tracing::error!(
                target: "talos_rpc",
                event_kind = "write_ceiling_read_failed",
                %actor_id,
                error = %e,
                "write-ceiling lookup failed — failing CLOSED, the mutation is refused"
            );
            CeilingRead::Unreadable
        }
    }
}

/// The gate as the subscribers call it: resolve enforcement, resolve the
/// ceiling, decide, and — on a refusal — emit the operator-facing record.
///
/// `op` MUST be one of the worker's own audit tokens (see
/// [`CONTROLLER_SERVED_WRITE_OPS`]), because `get_module_info`'s
/// `mutation_profile` promises operators that its labels correlate one-to-one
/// with refusal events.
///
/// ## Cost
///
/// Zero on a default deployment: the flag is read from a `OnceLock` and short
/// circuits before the query. With enforcement ON, one primary-key read of
/// `actors` — measured 2026-09-05 at **1.1 µs** server-side and **0.43 ms**
/// including the host round trip, against a memory `Set` that already performs
/// an embedding attempt, an AEAD encrypt and an upsert. See the module notes
/// in the PR for why a per-actor cache was rejected rather than merely
/// deferred: a TTL on a security rule is a window in which a revoked grant is
/// still honoured, and this path is measured at ~1 write/week on the dev
/// fleet.
pub(crate) async fn gate(
    pool: &sqlx::PgPool,
    actor_id: uuid::Uuid,
    op: &'static str,
    subject: &'static str,
    target: &str,
) -> CeilingDecision {
    // ONE reader of the flag in this process — the same `OnceLock` the #750
    // envelope gate consults. See the module docs.
    let enforced = talos_workflow_engine::write_ceiling_gate::controller_write_ceiling_enforced();
    if !enforced {
        return CeilingDecision::Permit;
    }
    let read = read_ceiling(pool, actor_id).await;
    let decision = decide(true, read);
    if let CeilingDecision::Refuse(reason) = decision {
        record_refusal(actor_id, op, subject, target, reason, read);
    }
    decision
}

/// Emit the operator-facing record of a refusal.
///
/// **Audit parity, and its stated limit.** `op` and `policy` are the EXACT
/// tokens the worker stamps on its `wasi:capability_denied` rows and the exact
/// tokens #750's envelope refusal uses, because the three are the same control
/// refusing the same thing by three transports. The parity is in the
/// VOCABULARY, not the transport: the worker's refusals also enter the
/// hash-chained WORM ledger and the controller has no `ExecutionLedger`
/// producer, so this reaches the `talos_audit` tracing target and the metrics
/// only — the same limit #750 recorded.
///
/// **`event_kind` is distinct on purpose.** A refusal HERE is a different
/// operational fact from a refusal at the envelope gate. The envelope route
/// has no worker-side gate at all, so refusing there is routine. This route
/// does: reaching it means a worker sent a mutation its OWN gate should have
/// refused, i.e. a FLEET-CONFIGURATION defect (an un-flagged or stale worker),
/// which is worth alerting on where the envelope refusal is not.
fn record_refusal(
    actor_id: uuid::Uuid,
    op: &'static str,
    subject: &'static str,
    target: &str,
    reason: RefusalReason,
    read: CeilingRead,
) {
    let ceiling = match read {
        CeilingRead::Found(c) => c.as_signing_str(),
        // Not "readonly": we did not read a ceiling, and reporting one we did
        // not read is the misleading-report class (#730/#736/#748) one level
        // down. The refusal stands; the field says why it is unknown.
        CeilingRead::NoSuchActor => "<no such actor>",
        CeilingRead::Unreadable => "<unreadable>",
    };
    tracing::warn!(
        target: "talos_audit",
        event_kind = "rpc_write_ceiling_refused",
        op,
        policy = talos_workflow_engine_core::WRITE_CEILING_POLICY,
        subject,
        %actor_id,
        reason = reason.as_str(),
        ceiling,
        target_preview = %target,
        "write-ceiling: signed-RPC mutation refused at the controller — the \
         sending worker did not refuse it itself, which means its \
         TALOS_WRITE_CEILING_ENFORCED is unset or its build predates the gate"
    );
    let Some(m) = talos_metrics::global() else {
        return;
    };
    // The signal that is SPECIFIC to this route, and the reason it needed its
    // own series. Reaching this gate means a worker sent a mutation its OWN
    // gate should have refused — a fleet-configuration defect. #757 routed
    // that fact to `event_kind = "rpc_write_ceiling_refused"` and to the
    // `talos_rpc` outcome tag, and MEASURED afterwards (2026-09-05, live
    // controller `/metrics/prometheus`) both are TRACING ONLY: no `talos_rpc*`
    // Prometheus series exists, and no RPC counter was registered. So the
    // fleet-config signal could not be selected by any alert — check 58/65's
    // class, a signal that exists as prose and not as a series.
    //
    // Incremented at the ONE chokepoint, for every subject, so a new
    // controller-served write op cannot forget it.
    m.rpc_write_ceiling_refusals_total
        .with_label_values(&[subject, reason.metric_label()])
        .inc();

    if op == talos_workflow_engine_core::AGENT_MEMORY_SET_OP
        || op == AGENT_MEMORY_DELETE_OP
        || op == AGENT_MEMORY_STORE_WITH_EMBEDDING_OP
    {
        // KEPT, deliberately, and the double count is documented rather than
        // silent. This counter answers a DIFFERENT question — "which
        // actor-memory writes did not land, and why" — and an operator asking
        // it must find every route in one place, which is the same reason #750
        // reused it for `invalid_key`. The two live alerts on it select
        // `reason="crypto"` and `reason="db"`, so a policy refusal still cannot
        // page anyone. Its HELP text names both routes, because a counter whose
        // description mentions only one of its two producers is this change's
        // own defect one level down.
        m.memory_write_failures_total
            .with_label_values(&["write_ceiling"])
            .inc();
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Audit probe
// ───────────────────────────────────────────────────────────────────────────

/// Exercise THIS gate — the signed-RPC mutation route — and inspect the result.
///
/// The twin of `talos_workflow_engine::write_ceiling_gate::probe_envelope_gate`,
/// and together they are what lets `security_audit` claim `round_trip` for the
/// controller half of the write ceiling instead of repeating the sentence "the
/// controller cannot exercise it from here", which stopped being true when
/// #750 and #757 landed.
///
/// # What it asserts, and why each arm
///
/// * `readonly` REFUSES, with `RefusalReason::Policy` — the rule working as
///   configured.
/// * `write` PERMITS. A gate that refuses everything is an outage, not a gate.
/// * **Both** unknown reads — `CeilingRead::NoSuchActor` and
///   `CeilingRead::Unreadable` — REFUSE, with `RefusalReason::Unreadable`.
///   This is the arm that matters most and the one no configuration check can
///   reach: a gate that cannot read its rule and permits has, during a database
///   incident, exactly the behaviour of no gate, while leaving logs implying one
///   ran. The reason must also be DISTINCT from the policy refusal, because "this
///   actor is readonly" and "I could not find out" send an operator to two
///   different places.
/// * With enforcement OFF every read PERMITS — the staged-rollout default,
///   byte-identical to pre-#757 behaviour.
///
/// # Cost
///
/// Pure and in-process: `decide` takes `enforced` as a parameter and the
/// database answer as a value, so this touches neither the env nor Postgres.
/// The DB-backed `CeilingRead` path is deliberately NOT probed — resolving a
/// real actor row would mean either writing a probe actor (a side effect in an
/// audit documented as side-effect free) or depending on one existing (a probe
/// that reports "broken" when the fixture is missing). What a live read adds
/// over this is coverage of `read_actor_write_ceiling`'s own SQL, which is
/// covered by `controller/tests/rpc_write_ceiling_tests.rs`.
///
/// # Errors
///
/// `Err(arm)` names the FIRST arm that behaved wrongly. No partial-success
/// shape: a gate that refuses correctly and permits wrongly is broken.
pub fn probe_rpc_gate() -> Result<(), &'static str> {
    if decide(true, CeilingRead::Found(WriteCeiling::ReadOnly))
        != CeilingDecision::Refuse(RefusalReason::Policy)
    {
        return Err("signed-RPC route: a readonly actor's mutation was PERMITTED");
    }
    if decide(true, CeilingRead::Found(WriteCeiling::Write)) != CeilingDecision::Permit {
        return Err("signed-RPC route: a write-capable actor's mutation was REFUSED");
    }
    for read in [CeilingRead::NoSuchActor, CeilingRead::Unreadable] {
        if decide(true, read) != CeilingDecision::Refuse(RefusalReason::Unreadable) {
            return Err(
                "signed-RPC route: an unreadable ceiling rule did NOT fail closed — during a \
                 database incident this gate permits every mutation",
            );
        }
    }
    for read in [
        CeilingRead::Found(WriteCeiling::ReadOnly),
        CeilingRead::Found(WriteCeiling::Write),
        CeilingRead::NoSuchActor,
        CeilingRead::Unreadable,
    ] {
        if decide(false, read) != CeilingDecision::Permit {
            return Err("signed-RPC route: enforcement is OFF but a mutation was refused anyway");
        }
    }
    Ok(())
}

// ── The op vocabulary, and the parity contract ──────────────────────────────

/// Worker audit token for an actor-memory delete. `talos_workflow_job_protocol`
/// exports only the `set` token (#750 needed only that one); these two are
/// spelled here rather than re-derived, and
/// `controller_ops_are_worker_ops` pins all of them against
/// `talos_capability_world::write_gated_ops` so a rename on the worker side
/// fails this crate's tests.
pub(crate) const AGENT_MEMORY_DELETE_OP: &str = "agent-memory-delete";
pub(crate) const AGENT_MEMORY_STORE_WITH_EMBEDDING_OP: &str = "agent-memory-store-with-embedding";
pub(crate) const INTEGRATION_STATE_SET_OP: &str = "integration-state-set";
pub(crate) const INTEGRATION_STATE_DELETE_OP: &str = "integration-state-delete";
pub(crate) const DATABASE_QUERY_OP: &str = "database-query";

/// Every ceiling-gated WORKER op whose mutation is actually PERFORMED BY THE
/// CONTROLLER, over a signed RPC subject — i.e. exactly the set this crate
/// must refuse when the worker did not.
///
/// The worker's full ceiling-gated set (`talos_capability_world::write_gated_ops`)
/// is larger, and the remainder is deliberately NOT here: `http-fetch`,
/// `http-fetch-all`, `webhook-send`, `email-send`, `graphql-execute`,
/// `messaging-publish`, `messaging-request`, `object-storage-put` and
/// `object-storage-delete` all egress from the WORKER process and never reach
/// a controller RPC subscriber, so the controller has no place to stand.
/// `complement_is_worker_local` pins that split, so a NEW ceiling-gated worker
/// op forces a decision here instead of silently landing in the ungated half.
///
/// `talos.state.write` is absent for a different and stronger reason: the
/// worker deliberately does NOT ceiling-gate execution `state` (it is
/// engine-internal durability, not the actor's data — `write_gated_ops`' own
/// docs say so), and `talos.graph.search`, `talos.ml.predict` and
/// `talos.ml.fewshot` are reads. Gating any of them here would make the
/// controller STRICTER than the worker, which is the same class of defect as
/// being laxer: one control, two answers.
pub const CONTROLLER_SERVED_WRITE_OPS: &[(&str, &str)] = &[
    (
        talos_workflow_engine_core::AGENT_MEMORY_SET_OP,
        talos_memory::memory_rpc::SUBJECT_MEMORY_OP,
    ),
    (
        AGENT_MEMORY_STORE_WITH_EMBEDDING_OP,
        talos_memory::memory_rpc::SUBJECT_MEMORY_OP,
    ),
    (
        AGENT_MEMORY_DELETE_OP,
        talos_memory::memory_rpc::SUBJECT_MEMORY_OP,
    ),
    (
        INTEGRATION_STATE_SET_OP,
        talos_memory::integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
    ),
    (
        INTEGRATION_STATE_DELETE_OP,
        talos_memory::integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
    ),
    (
        DATABASE_QUERY_OP,
        talos_memory::database_rpc::SUBJECT_DATABASE_QUERY,
    ),
];

#[cfg(test)]
mod write_ceiling_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn enforcement_off_permits_every_read_outcome() {
        // The staged-rollout default. Byte-identical to pre-change behaviour,
        // including for the failure reads — a deployment that has not opted in
        // must not start refusing because Postgres hiccuped.
        for read in [
            CeilingRead::Found(WriteCeiling::Write),
            CeilingRead::Found(WriteCeiling::ReadOnly),
            CeilingRead::NoSuchActor,
            CeilingRead::Unreadable,
        ] {
            assert_eq!(decide(false, read), CeilingDecision::Permit, "{read:?}");
        }
    }

    #[test]
    fn enforcement_on_refuses_readonly_and_permits_write() {
        assert_eq!(
            decide(true, CeilingRead::Found(WriteCeiling::ReadOnly)),
            CeilingDecision::Refuse(RefusalReason::Policy)
        );
        assert_eq!(
            decide(true, CeilingRead::Found(WriteCeiling::Write)),
            CeilingDecision::Permit
        );
    }

    #[test]
    fn an_unreadable_rule_fails_closed_with_its_own_reason() {
        // SECURITY: neither of these may PERMIT. And they must be
        // distinguishable from a policy refusal in the operator's logs —
        // "this actor is readonly" and "I could not find out" send an
        // operator to two different places.
        for read in [CeilingRead::NoSuchActor, CeilingRead::Unreadable] {
            assert_eq!(
                decide(true, read),
                CeilingDecision::Refuse(RefusalReason::Unreadable),
                "{read:?} must fail closed"
            );
        }
        assert_ne!(
            RefusalReason::Policy.as_str(),
            RefusalReason::Unreadable.as_str()
        );
    }

    #[test]
    fn the_decision_is_the_shared_predicate_not_a_local_copy() {
        // If `write_ceiling_denies` ever changes, this must change with it.
        // Pinning the agreement here is what stops a local re-derivation from
        // drifting — the defect #750 exists because of.
        for (enforced, ceiling) in [
            (true, WriteCeiling::ReadOnly),
            (true, WriteCeiling::Write),
            (false, WriteCeiling::ReadOnly),
            (false, WriteCeiling::Write),
        ] {
            let shared = write_ceiling_denies(enforced, ceiling);
            let ours = decide(enforced, CeilingRead::Found(ceiling)).is_refused();
            assert_eq!(shared, ours, "enforced={enforced} ceiling={ceiling:?}");
        }
    }

    /// Every op the controller gates must be an op the WORKER gates, spelled
    /// identically. A rename on either side fails here rather than silently
    /// breaking the `mutation_profile` ↔ audit-event correlation
    /// `get_module_info` promises operators.
    #[test]
    fn controller_ops_are_worker_ops() {
        let worker: HashSet<&str> = talos_capability_world::write_gated_ops(
            &talos_capability_world::CapabilityWorld::Trusted,
        )
        .into_iter()
        .collect();
        for (op, _subject) in CONTROLLER_SERVED_WRITE_OPS {
            assert!(
                worker.contains(op),
                "`{op}` is gated by the controller but is not in the worker's \
                 write_gated_ops — one control, two vocabularies"
            );
        }
    }

    /// The complement. Every worker-gated op the controller does NOT gate must
    /// be one the controller structurally CANNOT gate, because the mutation
    /// happens inside the worker process and never reaches a subscriber.
    ///
    /// This is the half that keeps the list honest: without it, a NEW
    /// ceiling-gated worker op would land in the ungated remainder and nothing
    /// would say so. Adding one now fails this test until someone decides
    /// which half it belongs in.
    #[test]
    fn complement_is_worker_local() {
        const WORKER_LOCAL_EGRESS_OPS: &[&str] = &[
            "http-fetch",
            "http-fetch-all",
            "webhook-send",
            "email-send",
            "graphql-execute",
            "messaging-publish",
            "messaging-request",
            "object-storage-put",
            "object-storage-delete",
        ];
        let controller: HashSet<&str> = CONTROLLER_SERVED_WRITE_OPS
            .iter()
            .map(|(op, _)| *op)
            .collect();
        let worker_local: HashSet<&str> = WORKER_LOCAL_EGRESS_OPS.iter().copied().collect();
        let worker: HashSet<&str> = talos_capability_world::write_gated_ops(
            &talos_capability_world::CapabilityWorld::Trusted,
        )
        .into_iter()
        .collect();

        let unaccounted: Vec<&str> = worker
            .iter()
            .copied()
            .filter(|op| !controller.contains(op) && !worker_local.contains(op))
            .collect();
        assert!(
            unaccounted.is_empty(),
            "these worker ceiling-gated ops are in neither half — decide \
             whether the controller serves them over RPC (add to \
             CONTROLLER_SERVED_WRITE_OPS and gate it) or whether they are \
             worker-local egress (add to WORKER_LOCAL_EGRESS_OPS): \
             {unaccounted:?}"
        );
        // And nothing may be claimed worker-local that the worker does not
        // actually gate — a stale entry here would silently excuse a real op.
        for op in WORKER_LOCAL_EGRESS_OPS {
            assert!(
                worker.contains(op),
                "`{op}` is listed as worker-local egress but the worker does \
                 not ceiling-gate it — stale entry"
            );
        }
    }

    /// The audit's `round_trip` claim for the signed-RPC half rests entirely
    /// on this returning `Ok`. A REGRESSION guard, not a restatement of the
    /// `decide` tests above: those call `decide` directly, so all of them
    /// could pass while the probe — the thing a running controller executes —
    /// was wired wrong.
    #[test]
    fn the_audit_probe_finds_this_gate_healthy() {
        assert_eq!(probe_rpc_gate(), Ok(()));
    }

    /// Two spellings of one fact must not drift. The log token is the
    /// worker's vocabulary; the metric label is the dashboard's. An operator
    /// correlating a `talos_rpc_write_ceiling_refusals_total{reason="policy"}`
    /// bump against `event_kind=rpc_write_ceiling_refused reason=write_ceiling`
    /// needs the pairing to be stable, and both come from exhaustive matches
    /// so a third variant cannot skip either.
    #[test]
    fn refusal_reason_spellings_stay_paired() {
        for (r, log, metric) in [
            (RefusalReason::Policy, "write_ceiling", "policy"),
            (
                RefusalReason::Unreadable,
                "write_ceiling_unreadable",
                "unreadable",
            ),
        ] {
            assert_eq!(r.as_str(), log);
            assert_eq!(r.metric_label(), metric);
        }
        assert_ne!(
            RefusalReason::Policy.metric_label(),
            RefusalReason::Unreadable.metric_label()
        );
    }

    /// A refusal MOVES the counter.
    ///
    /// This drives the production recorder — the function `gate` calls on
    /// every refusal — rather than a test-local copy, which is the whole
    /// point: the seeding test in `talos-metrics` passes whether or not
    /// anything increments, so it cannot tell a wired counter from a dead one
    /// (check 58's class). Deleting the `.inc()` in `record_refusal` fails
    /// HERE and nowhere else.
    ///
    /// `gate` itself is not driven because it needs a `PgPool` and reads the
    /// process flag from a `OnceLock` that a unit test cannot flip; the SQL
    /// and the end-to-end refusal are covered by
    /// `controller/tests/rpc_write_ceiling_tests.rs`.
    #[test]
    fn a_refusal_moves_the_rpc_counter() {
        talos_metrics::set_global(
            talos_metrics::TalosMetrics::new().expect("build a metrics registry"),
        );
        let m = talos_metrics::global().expect("global metrics installed");
        let subject = talos_memory::memory_rpc::SUBJECT_MEMORY_OP;

        // Deltas, not absolutes: `set_global` is a process-wide `OnceLock`
        // and other tests in this binary may have stamped the same series.
        let before_policy = m
            .rpc_write_ceiling_refusals_total
            .with_label_values(&[subject, "policy"])
            .get();
        let before_unreadable = m
            .rpc_write_ceiling_refusals_total
            .with_label_values(&[subject, "unreadable"])
            .get();
        let before_memory = m
            .memory_write_failures_total
            .with_label_values(&["write_ceiling"])
            .get();

        record_refusal(
            uuid::Uuid::nil(),
            talos_workflow_engine_core::AGENT_MEMORY_SET_OP,
            subject,
            "probe/key",
            RefusalReason::Policy,
            CeilingRead::Found(WriteCeiling::ReadOnly),
        );
        record_refusal(
            uuid::Uuid::nil(),
            DATABASE_QUERY_OP,
            talos_memory::database_rpc::SUBJECT_DATABASE_QUERY,
            "INSERT",
            RefusalReason::Unreadable,
            CeilingRead::Unreadable,
        );
        record_refusal(
            uuid::Uuid::nil(),
            AGENT_MEMORY_DELETE_OP,
            subject,
            "probe/key",
            RefusalReason::Unreadable,
            CeilingRead::NoSuchActor,
        );

        assert_eq!(
            m.rpc_write_ceiling_refusals_total
                .with_label_values(&[subject, "policy"])
                .get()
                - before_policy,
            1.0,
            "the policy refusal did not move the RPC counter"
        );
        assert_eq!(
            m.rpc_write_ceiling_refusals_total
                .with_label_values(&[subject, "unreadable"])
                .get()
                - before_unreadable,
            1.0,
            "the fail-closed refusal did not move the RPC counter"
        );
        // The database subject is counted too — #757 counted NOTHING for it.
        assert_eq!(
            m.rpc_write_ceiling_refusals_total
                .with_label_values(&[
                    talos_memory::database_rpc::SUBJECT_DATABASE_QUERY,
                    "unreadable"
                ])
                .get(),
            1.0,
            "a database-route refusal must be counted, not only logged"
        );
        // And the shared "row did not land" counter still moves for the two
        // actor-memory ops (and only those) — the documented double count.
        assert_eq!(
            m.memory_write_failures_total
                .with_label_values(&["write_ceiling"])
                .get()
                - before_memory,
            2.0,
            "the memory-route refusals must still reach the shared counter"
        );
    }

    /// Every `(subject, reason)` the chokepoint can write must be one
    /// `talos-metrics` pre-seeds, or the series is ABSENT until the first
    /// refusal — and `increase(...) > 0` over an absent series matches
    /// nothing, which is the alert silenced by exactly the condition it
    /// detects. The seed list cannot live in this crate (`talos-metrics` is a
    /// dependency, not a dependent), so this is the pin that keeps the two
    /// halves in agreement.
    #[test]
    fn every_gated_subject_is_seeded_in_the_metrics_crate() {
        let seeded: HashSet<&str> = talos_metrics::RPC_WRITE_CEILING_SUBJECTS
            .iter()
            .copied()
            .collect();
        let gated: HashSet<&str> = CONTROLLER_SERVED_WRITE_OPS
            .iter()
            .map(|(_, subject)| *subject)
            .collect();
        assert_eq!(
            seeded, gated,
            "the pre-seeded subjects and the gated subjects disagree — a \
             subject in `gated` but not `seeded` has an absent series until \
             its first refusal; one in `seeded` but not `gated` implies a \
             wired signal that does not exist"
        );
    }

    #[test]
    fn every_gated_op_names_a_real_subject() {
        for (op, subject) in CONTROLLER_SERVED_WRITE_OPS {
            assert!(
                subject.starts_with("talos."),
                "`{op}` names `{subject}`, which is not a talos NATS subject"
            );
        }
    }
}
