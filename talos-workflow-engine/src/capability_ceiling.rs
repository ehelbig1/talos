//! The dispatch-time capability-world ceiling gate.
//!
//! `actors.max_capability_world` is checked at trigger time by
//! `talos_workflow_authorization::authorize_workflow_trigger`, over the
//! modules of the PARENT graph. Child workflows — `sub_workflow`, judge,
//! ensemble, reflective-retry, llm-dispatch, capability-dispatch, agent-loop
//! bodies — are resolved at RUN time, and their modules never met that
//! gate: a `minimal-node` actor whose parent graph was clean could run an
//! `automation-node` module one `sub_workflow` hop down. The engine already
//! narrows the LLM tier, write ceiling and egress scope at the sub-engine
//! boundary; the world axis had no runtime enforcement at all.
//!
//! This is that enforcement: one pure decision, applied at BOTH module
//! dispatch sites (single-node and pipeline-step), reading the ceiling the
//! `AdapterSet` copies into every sub-engine. The decision itself is
//! `talos_capability_world::ceiling_permits` (the lattice, fail-closed on an
//! unknown world on either side) — lint check 33 forbids a local re-impl.

/// Refuse `module_world` under `ceiling`, or permit it.
///
/// * `ceiling == None` → permitted. No ceiling is bound: an actor-less
///   engine, or the ceiling-exempt default actor.
/// * Otherwise the lattice decides. An UNKNOWN world on either side is a
///   refusal (`ceiling_permits` is fail-closed) — a typo'd module world or a
///   malformed actor row must not read as "fits".
///
/// The `Err` is the node-failure message: it names the module, both worlds
/// and the fix, because the operator reading it did not necessarily author
/// the child workflow that carried the module in.
pub(crate) fn refuse_module_over_ceiling(
    ceiling: Option<&str>,
    module_id: uuid::Uuid,
    module_world: &str,
) -> Result<(), String> {
    let Some(ceiling) = ceiling else {
        return Ok(());
    };
    if talos_capability_world::ceiling_permits(ceiling, module_world) {
        return Ok(());
    }
    Err(format!(
        "capability ceiling violation: module {module_id} requires world \
         '{module_world}' but the bound actor's max_capability_world is \
         '{ceiling}'. Grant the actor a wider ceiling \
         (grant_capability_ceiling) or use a module compiled for a narrower \
         world. This gate runs at dispatch so a sub-workflow / judge / \
         ensemble child cannot carry a module past the actor's ceiling."
    ))
}

#[cfg(test)]
mod tests {
    use super::refuse_module_over_ceiling;
    use uuid::Uuid;

    #[test]
    fn no_ceiling_permits_everything() {
        let id = Uuid::new_v4();
        for world in [
            "minimal-node",
            "automation-node",
            "governance-node",
            "stub",
            "",
        ] {
            assert!(
                refuse_module_over_ceiling(None, id, world).is_ok(),
                "{world}"
            );
        }
    }

    #[test]
    fn a_module_within_the_ceiling_is_permitted() {
        let id = Uuid::new_v4();
        assert!(refuse_module_over_ceiling(Some("automation-node"), id, "minimal-node").is_ok());
        assert!(refuse_module_over_ceiling(Some("http-node"), id, "http-node").is_ok());
        assert!(refuse_module_over_ceiling(Some("agent-node"), id, "secrets-node").is_ok());
    }

    #[test]
    fn a_module_above_the_ceiling_is_refused_and_the_message_names_both_worlds() {
        let id = Uuid::new_v4();
        let err = refuse_module_over_ceiling(Some("minimal-node"), id, "automation-node")
            .expect_err("automation-node does not fit under minimal-node");
        assert!(err.contains(&id.to_string()));
        assert!(err.contains("'automation-node'"));
        assert!(err.contains("'minimal-node'"));
        assert!(err.contains("grant_capability_ceiling"));
    }

    #[test]
    fn lattice_incomparable_siblings_are_refused() {
        // `cache-node` ⊄ `secrets-node` and vice versa — the case the linear
        // rank gate got wrong and the lattice gate exists for.
        let id = Uuid::new_v4();
        assert!(refuse_module_over_ceiling(Some("cache-node"), id, "secrets-node").is_err());
    }

    #[test]
    fn an_unknown_world_on_either_side_fails_closed() {
        let id = Uuid::new_v4();
        assert!(refuse_module_over_ceiling(Some("minimal-node"), id, "stub").is_err());
        assert!(refuse_module_over_ceiling(Some("not-a-world"), id, "minimal-node").is_err());
    }
}
