//! Source pins for the `allowed_secrets` permission-vs-delivery split.
//!
//! `allowed_secrets` has two jobs with different vocabularies: it is matched as
//! a PERMISSION boundary by `vault_path_permitted` (exact / prefix / glob /
//! `*`) and used VERBATIM as a DELIVERY path list by the engine, which hands it
//! to a `WHERE key_path = ANY($1)` query where only an exact path or `*`
//! resolves. A prefix or glob grant therefore permits a path and delivers
//! nothing, silently — an empty result is `Ok`.
//!
//! These are TEXTUAL pins, stated as such: they prove the call sites exist and
//! that the deliberate exclusion below is still deliberate. What the delivery
//! predicate ANSWERS is pinned by `vault_matcher_tests` in
//! `talos-workflow-job-protocol`, beside the permission matcher it disagrees
//! with. Driving `handle_test_secret_access` end to end needs an `McpState`
//! with a database and a vault, which is why the call site gets a pin and not a
//! test — the same division of labour checks 74b/79b describe.

#[cfg(test)]
mod tests {
    const MODULES: &str = include_str!("modules.rs");
    const SANDBOX: &str = include_str!("sandbox.rs");

    /// Needles are ASSEMBLED rather than written out so a pin can never vouch
    /// for itself by matching its own source line.
    fn needle(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn the_prefetch_gate_consults_the_shared_delivery_predicate() {
        let call = needle(&["vault_path_", "prefetched(&allowed_secrets"]);
        assert_eq!(
            MODULES.matches(call.as_str()).count(),
            1,
            "test_secret_access must decide delivery with the shared predicate, \
             exactly once — a hand-rolled copy is how the two matchers drift"
        );
    }

    #[test]
    fn the_prefetch_gate_is_reported_to_the_caller() {
        let arr = needle(&["gate_allowlist, gate_presence, gate_", "prefetch]"]);
        assert!(
            MODULES.contains(arr.as_str()),
            "the dispatch_prefetch gate must be in the `gates` array the caller \
             reads; computing it and dropping it is the silence this closes"
        );
    }

    /// The decision this package is most likely to have "fixed" for it later.
    ///
    /// Gate 5 must NOT join `would_succeed`. A path the grant does not
    /// pre-fetch can still be delivered by a `vault://<path>` reference in the
    /// node's own config — the route every OAuth integration uses, and one this
    /// tool cannot see, because it takes a module and a path and no node. The
    /// bare-prefix `oauth/gmail` grants on this fleet are CORRECT, so folding
    /// gate 5 into the verdict would flip `would_succeed` to false for modules
    /// that demonstrably work: a determinate negative over an unmeasured route,
    /// which is the same defect in the other direction.
    #[test]
    fn the_prefetch_gate_is_deliberately_not_in_the_verdict() {
        let line = MODULES
            .lines()
            .find(|l| l.contains("let all_pass"))
            .expect("the `would_succeed` conjunction must still exist");
        assert!(
            !line.contains("prefetch"),
            "gate 5 was folded into `would_succeed`: {line}\n\
             Read this test's doc comment — the config-reference delivery route \
             is invisible here, so this would report failure over something \
             never measured."
        );
        // Control: the four gates it IS built from are still all present, so
        // this cannot pass because the conjunction was gutted instead.
        for g in ["world_allowed", "is_reserved", "allow_pass", "exists"] {
            assert!(line.contains(g), "verdict lost its `{g}` term: {line}");
        }
    }

    #[test]
    fn every_operator_surface_names_the_shared_delivery_sentence() {
        let c = needle(&["SECRET_GRANT_DELIVERY", "_NOTE"]);
        // One in test_secret_access's own description; three across the
        // compile / update writer schemas. Counted, not merely present: a
        // surface that drops it must fail rather than ride on a sibling.
        assert_eq!(
            MODULES.matches(c.as_str()).count(),
            1,
            "test_secret_access's description must carry the shared sentence"
        );
        assert_eq!(
            SANDBOX.matches(c.as_str()).count(),
            3,
            "compile_custom_sandbox's allowed_secrets, update_module_secrets' \
             description and its allowed_secrets param must each carry it — \
             these are the surfaces that recommended the non-delivering form"
        );
    }

    /// Gate 3's own remedy text was the FOURTH surface recommending the
    /// non-delivering form ("Add it (exact path or prefix) and recompile").
    /// It is a per-path sentence rather than a static description, so the
    /// shared-const count pin above cannot see it.
    #[test]
    fn the_allowlist_gate_no_longer_recommends_a_prefix_grant() {
        for stale in ["exact path or prefix)", "or a prefix grant."] {
            assert!(
                !MODULES.contains(stale),
                "gate 3 is recommending the form that permits without \
                 delivering: {stale:?}"
            );
        }
        // Control: it must still offer a remedy at all.
        assert!(MODULES.contains("Add the EXACT path"));
    }

    /// Gate 1 must know about BOTH routes a secret takes to a module. Testing
    /// only the guest interface made it 0-for-38 on this fleet — every live
    /// node carrying a `vault://` config reference is `http-node` — and its
    /// remedy told the operator to recompile 14 modules at a HIGHER capability
    /// world, which would widen privilege and fix nothing.
    #[test]
    fn the_capability_gate_consults_both_secret_routes() {
        for (what, p) in [
            (
                "guest",
                needle(&["world_allows_", "secrets(&capability_world)"]),
            ),
            (
                "host",
                needle(&["world_allows_vault_", "substitution(&capability_world)"]),
            ),
        ] {
            assert_eq!(
                MODULES.matches(p.as_str()).count(),
                1,
                "gate 1 must consult the {what} route exactly once"
            );
        }
        let or = needle(&["let world_allowed = guest_route ", "|| host_route;"]);
        assert!(
            MODULES.contains(or.as_str()),
            "the gate must pass when EITHER route is available; an AND here \
             refuses every http-node module that works by host substitution"
        );
    }

    /// The remedy that would have widened 14 modules' capability world.
    #[test]
    fn the_capability_gate_no_longer_advises_recompiling_over_the_host_route() {
        let stale = needle(&["does NOT import the secrets interface. ", "Recompile with"]);
        assert!(
            !MODULES.contains(stale.as_str()),
            "gate 1 is again telling a working host-route module to recompile"
        );
        // Control: the genuinely-unreachable case must STILL advise a recompile.
        assert!(
            MODULES.contains("can reach a secret by neither route"),
            "a world with no route at all must still get an actionable remedy"
        );
    }

    #[test]
    fn the_gate_count_in_the_description_matches_the_gates_returned() {
        let five = needle(&["Reports FIVE", " gates"]);
        assert!(
            MODULES.contains(five.as_str()),
            "the tool description must state the gate count it actually returns"
        );
        assert!(
            !MODULES.contains("the same three gates"),
            "the stale 'three gates' claim (which listed four) must be gone"
        );
    }
}
