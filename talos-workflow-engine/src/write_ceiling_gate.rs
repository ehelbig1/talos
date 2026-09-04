//! Controller-side write-ceiling gate for the `__memory_write__` envelope.
//!
//! # Why this exists
//!
//! `actors.max_write_ceiling` is one control with two enforcement surfaces,
//! and until #750 only one of them existed.
//!
//! A module reaches `actor_memory` two ways:
//!
//! 1. **Host call.** `agent_memory::set` inside the guest → signed NATS RPC →
//!    controller. The worker gates this at
//!    `talos_worker_runtime::context::TalosContext::write_ceiling_refuses`
//!    and returns `NotAvailable` to the guest for a `readonly` actor.
//! 2. **Returned value.** The module returns
//!    `{"__memory_write__": {"key": …, "value": …}}` and the CONTROLLER
//!    persists it on node completion
//!    (`talos_engine::node_hook::ControllerNodeHook`). That path had **no**
//!    ceiling reference of any kind.
//!
//! Path 2 needs no capability at all: a `minimal-node` module — one whose
//! `get_module_info.mutation_profile` correctly reports that it can mutate
//! *nothing*, because `talos_capability_world::write_gated_ops(Minimal)` is
//! empty — writes durable actor memory simply by returning a JSON object.
//! Proven live 2026-09-04: actor `probe-750-readonly`
//! (`max_write_ceiling = 'readonly'`) ran a one-node `minimal-node` workflow,
//! the execution completed, and `actor_memory` gained a row. Neither process
//! logged a gate decision, because neither process made one.
//!
//! So the ceiling bounded what a module could do through host calls and
//! nothing it could do by returning a value.
//!
//! # What this module does
//!
//! [`apply_memory_write_ceiling`] is the controller's half of the gate. It is
//! **pure** — `enforced` is a parameter, not an env read — so the rule is
//! testable without a process env, and it shares the actual DECISION with the
//! worker via [`talos_workflow_engine_core::write_ceiling_denies`] rather than
//! re-deriving it. Two paths disagreeing about one control is the defect; a
//! hand-copied predicate is how it would come back.
//!
//! # What it deliberately does NOT do
//!
//! It does not fail the node. See [`apply_memory_write_ceiling`] for the
//! argument, which is drawn from what the worker path actually does rather
//! than from what it looks like it does.

use serde_json::Value as JsonValue;
use talos_workflow_engine_core::reserved_keys;
use talos_workflow_engine_core::{write_ceiling_denies, WriteCeiling};

/// Ceiling on the refused key echoed back into the node output. The key is
/// module-authored, so it is bounded for the same reason
/// `ControllerNodeHook` bounds its log preview: a pathological
/// `MEMORY_WRITE_KEY` must not amplify into every downstream node's gathered
/// inputs and the stored execution output.
const MAX_REFUSED_KEY_CHARS: usize = 120;

/// Whether the controller enforces the per-actor write ceiling.
///
/// # Why the controller reads its own flag
///
/// The worker's gate is staged behind `TALOS_WRITE_CEILING_ENFORCED`, read
/// once at boot in the worker process. **The controller cannot read the
/// worker's env**, so it must decide for itself what "enforced" means. Two
/// options were weighed:
///
/// * **Unconditional.** Apply the ceiling from the actor row always. Rejected:
///   `actors.max_write_ceiling` DEFAULTS to `readonly` for every actor created
///   after the introducing migration, so shipping this unconditionally would
///   silently start refusing `__memory_write__` for every such actor on every
///   deployment — including the ones that never opted into enforcement. That
///   is a fleet-wide, un-announced privilege reduction, and it contradicts the
///   staged-rollout shape this platform uses for exactly this class of change
///   (`TALOS_ENVELOPE_SEALING`, the tier ceiling, strict egress).
/// * **Its own flag, same name.** Chosen. An operator who has already decided
///   "the write ceiling is a live control" sets one variable; both processes
///   then agree. The default-off behaviour is byte-identical to today.
///
/// The cost of the choice is stated rather than hidden: **until the variable
/// is also set on the controller, the gap this module closes stays open.**
/// `docker-compose.yml` and `deploy/helm/talos/values.yaml` set it on the
/// worker only, and the chart's own comment claimed *"controller side needs no
/// change … Worker-only env."* Both are corrected in the same change.
///
/// Read once and cached: this sits on the node-completion path.
pub fn controller_write_ceiling_enforced() -> bool {
    static ENFORCED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENFORCED
        .get_or_init(|| talos_config::bool_env_or_default("TALOS_WRITE_CEILING_ENFORCED", false))
}

/// The key a refused `__memory_write__` envelope asked for, as it should be
/// reported. Returned so the caller can log/audit it; the same value is
/// written into the node output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusedMemoryWrite {
    /// Requested memory key, already redacted by the caller and truncated
    /// here. `"<missing>"` when the envelope carried no string `key`.
    pub key: String,
}

/// Apply the write ceiling to one node (or pipeline-step) output.
///
/// Returns `Some(RefusedMemoryWrite)` when an envelope was refused, `None`
/// otherwise. On refusal the output is REWRITTEN in place:
///
/// * `__memory_write__` is **removed**, so no later consumer — the lifecycle
///   hook, a `test_module` re-run, a future reader of the stored output — can
///   act on a write that policy refused. Annotating without removing would
///   leave the envelope one `unwrap_or(false)` away from being honoured.
/// * `__memory_write_refused__` is **inserted**, carrying the requested key,
///   the policy token and the ceiling, so nothing downstream asserts a write
///   that did not happen. The module's own success language (`"written_key"`)
///   is left alone: a module's free-form fields are not the engine's to
///   police, and this key is the authoritative signal beside them. That limit
///   is real and is stated rather than implied.
///
/// `__memory_write_refused__` is removed UNCONDITIONALLY on every call, before
/// any decision, because it is engine-authored: a module that emits its own
/// copy — or a node whose output inherited one from upstream — must not be
/// able to fabricate a refusal record. Set-or-REMOVE, never set-or-inherit;
/// the rule `build_judge_envelope` learned and the inbound reserved-key strip
/// enforces on trigger payloads.
///
/// # Why the node COMPLETES rather than fails
///
/// The tempting answer is "the worker returns `NotAvailable`, the module
/// errors, the node fails — do the same". That reads the worker path as
/// stricter than it is. `write_ceiling_refuses` returns an `Err` **to the
/// guest**; whether the node fails is then the module's choice — a guest that
/// ignores the result of `set` completes successfully with its memory write
/// silently refused, which is the same outcome this function produces, minus
/// the annotation. So node failure is not a property of the worker path; it is
/// a property of some guests on it.
///
/// Against that, three reasons to complete:
///
/// 1. Every other `__memory_write__` failure — invalid key, DB error, no bound
///    actor — is best-effort by explicit contract: log, count, do not stall the
///    execution. A policy refusal is the weakest reason of the four to become
///    the only fatal one.
/// 2. Failing would make enabling a flag a CONTROL-FLOW change: workflows that
///    today complete would begin aborting. That is a much larger blast radius
///    than the gap warrants, and it is the kind of change an operator should
///    opt into separately.
/// 3. The refusal is not silent, which is the actual requirement. It is in the
///    node output, in a structured WARN, in the audit stream, and in
///    `talos_memory_write_failures_total{reason="write_ceiling"}`.
///
/// A future `on_refusal: "fail"` per-node policy would be a clean addition;
/// it is deliberately not this change.
pub(crate) fn apply_memory_write_ceiling(
    output: &mut JsonValue,
    ceiling: WriteCeiling,
    enforced: bool,
    redact: impl Fn(&str) -> String,
) -> Option<RefusedMemoryWrite> {
    let obj = output.as_object_mut()?;

    // Engine-authored: strip any caller-supplied copy FIRST and on EVERY
    // call, including the ones that go on to permit the write.
    obj.remove(reserved_keys::MEMORY_WRITE_REFUSED);

    if !obj.contains_key(reserved_keys::MEMORY_WRITE) {
        return None;
    }
    if !write_ceiling_denies(enforced, ceiling) {
        return None;
    }

    let envelope = obj.remove(reserved_keys::MEMORY_WRITE)?;
    let key_raw = envelope
        .get("key")
        .and_then(JsonValue::as_str)
        .unwrap_or("<missing>");
    let key: String = redact(key_raw)
        .chars()
        .take(MAX_REFUSED_KEY_CHARS)
        .collect();

    obj.insert(
        reserved_keys::MEMORY_WRITE_REFUSED.to_string(),
        serde_json::json!({
            "key": key,
            "reason": talos_workflow_engine_core::WRITE_CEILING_POLICY,
            "ceiling": ceiling.as_signing_str(),
        }),
    );
    Some(RefusedMemoryWrite { key })
}

#[cfg(test)]
mod tests {
    use super::{apply_memory_write_ceiling, RefusedMemoryWrite};
    use serde_json::json;
    use talos_workflow_engine_core::reserved_keys::{MEMORY_WRITE, MEMORY_WRITE_REFUSED};
    use talos_workflow_engine_core::WriteCeiling;

    fn passthrough(s: &str) -> String {
        s.to_string()
    }

    /// The live #750 shape: a readonly actor, enforcement on, an envelope in
    /// the output. The envelope must be GONE (not merely flagged) and the
    /// refusal must be recorded.
    #[test]
    fn readonly_enforced_refuses_and_annotates() {
        let mut out = json!({
            "__memory_write__": {"key": "probe750", "memory_type": "working", "value": {"a": 1}},
            "written_key": "probe750"
        });
        let refused =
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, true, passthrough);
        assert_eq!(
            refused,
            Some(RefusedMemoryWrite {
                key: "probe750".into()
            })
        );
        assert!(
            out.get(MEMORY_WRITE).is_none(),
            "the envelope must be removed, not just flagged — a downstream \
             reader must not be able to honour a refused write"
        );
        assert_eq!(out[MEMORY_WRITE_REFUSED]["key"], "probe750");
        assert_eq!(out[MEMORY_WRITE_REFUSED]["reason"], "write-ceiling");
        assert_eq!(out[MEMORY_WRITE_REFUSED]["ceiling"], "readonly");
        // Stated limit, pinned so it is not mistaken for coverage: the
        // module's own success language survives. The engine-authored key is
        // the authoritative signal beside it.
        assert_eq!(out["written_key"], "probe750");
    }

    #[test]
    fn write_ceiling_permits() {
        let mut out = json!({"__memory_write__": {"key": "k"}});
        assert!(
            apply_memory_write_ceiling(&mut out, WriteCeiling::Write, true, passthrough).is_none()
        );
        assert!(out.get(MEMORY_WRITE).is_some());
        assert!(out.get(MEMORY_WRITE_REFUSED).is_none());
    }

    /// Default (flag off) must be byte-identical to pre-#750 behaviour.
    #[test]
    fn unenforced_is_inert_even_for_readonly() {
        let mut out = json!({"__memory_write__": {"key": "k"}});
        assert!(
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, false, passthrough)
                .is_none()
        );
        assert!(out.get(MEMORY_WRITE).is_some());
    }

    /// Engine-authored keys are never caller-authorable. A module that emits
    /// its own refusal marker must not be able to fabricate one — on the
    /// PERMIT path, where nothing else would remove it.
    #[test]
    fn caller_supplied_refusal_marker_is_stripped_on_the_permit_path() {
        let mut out = json!({
            "__memory_write__": {"key": "k"},
            "__memory_write_refused__": {"key": "fabricated", "reason": "write-ceiling"}
        });
        assert!(
            apply_memory_write_ceiling(&mut out, WriteCeiling::Write, true, passthrough).is_none()
        );
        assert!(out.get(MEMORY_WRITE_REFUSED).is_none());
        assert!(out.get(MEMORY_WRITE).is_some());
    }

    /// …and on the path with no envelope at all, where an inherited marker
    /// would otherwise claim a refusal for a node that never asked to write.
    #[test]
    fn caller_supplied_refusal_marker_is_stripped_with_no_envelope() {
        let mut out = json!({"__memory_write_refused__": true, "result": 1});
        assert!(
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, true, passthrough)
                .is_none()
        );
        assert!(out.get(MEMORY_WRITE_REFUSED).is_none());
    }

    #[test]
    fn refused_key_is_redacted_and_bounded() {
        let long = format!("sk-ant-{}", "x".repeat(500));
        let mut out = json!({ "__memory_write__": {"key": long} });
        let refused =
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, true, |s: &str| {
                // Stand-in for the engine's DLP sanitizer.
                s.replace("sk-ant-", "[REDACTED]")
            })
            .expect("refused");
        assert!(refused.key.starts_with("[REDACTED]"));
        assert!(refused.key.chars().count() <= super::MAX_REFUSED_KEY_CHARS);
    }

    #[test]
    fn envelope_without_a_key_still_refuses() {
        let mut out = json!({"__memory_write__": {"value": 1}});
        let refused =
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, true, passthrough)
                .expect("refused");
        assert_eq!(refused.key, "<missing>");
        assert!(out.get(MEMORY_WRITE).is_none());
    }

    #[test]
    fn non_object_output_is_untouched() {
        let mut out = json!([1, 2, 3]);
        assert!(
            apply_memory_write_ceiling(&mut out, WriteCeiling::ReadOnly, true, passthrough)
                .is_none()
        );
        assert_eq!(out, json!([1, 2, 3]));
    }

    /// The controller's audit label must be a label the WORKER actually uses
    /// for this operation — `get_module_info.mutation_profile` promises
    /// operators the two correlate one-to-one. Pinned structurally against
    /// the capability-world vocabulary rather than against a second copy of
    /// the string.
    #[test]
    fn audit_op_label_is_in_the_worker_vocabulary() {
        let agent_ops = talos_capability_world::write_gated_ops(
            &talos_capability_world::CapabilityWorld::Agent,
        );
        assert!(
            agent_ops.contains(&talos_workflow_engine_core::AGENT_MEMORY_SET_OP),
            "controller-side refusal audits under a label the worker never emits"
        );
    }
}
