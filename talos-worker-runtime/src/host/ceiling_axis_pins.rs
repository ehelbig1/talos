//! The write-ceiling AXIS PARTITION, pinned at every gate site.
//!
//! The partition is the security boundary this package exists to draw: THREE
//! gates infer "is this a mutation?" from the HTTP verb and are separately
//! overridable; TWELVE are categorical or AST-proven and are not. An actor
//! granted the verb override must NOT thereby gain `email-send`,
//! `messaging-publish`, `agent-memory-set` or any other categorical op.
//!
//! # Why a pin and not only tests
//!
//! The decision itself is unit-tested in `talos-workflow-engine-core`, and
//! those tests are blind to which axis a CALL SITE passes — measured, not
//! assumed: mutating `email.rs` from `Categorical` to `VerbInferred`, and
//! `graphql.rs` from `VerbInferred` to `Categorical`, both left the entire
//! core + worker suite green. A guard at the primitive cannot see a call site
//! (checks 74b/79b). Driving the gates end to end needs a live `TalosContext`,
//! a process-global enforcement flag that sibling tests race (check 82's own
//! objection) and a real host call, so this pin is what fits in a unit test —
//! and it is TEXTUAL, which it says rather than implies.

/// Every `(op label, axis)` pair the worker's gate sites declare.
fn declared_axes() -> Vec<(String, String)> {
    // Assembled needles: this file must not vouch for itself.
    let inferred = format!("CeilingAxis::{}", "VerbInferred");
    let categorical = format!("CeilingAxis::{}", "Categorical");

    let files: [&str; 10] = [
        include_str!("http.rs"),
        // The raw `wasi:http` gate (trusted world, 2026-09-25): a second
        // `http-fetch` site on the verb axis, so the op SET is unchanged.
        include_str!("wasi_http.rs"),
        include_str!("graphql.rs"),
        include_str!("webhook.rs"),
        include_str!("email.rs"),
        include_str!("memory.rs"),
        include_str!("messaging.rs"),
        include_str!("database.rs"),
        include_str!("object_storage.rs"),
        include_str!("integration_state.rs"),
    ];

    let mut out = Vec::new();
    for src in files {
        let prod = crate::host::ceiling_axis_pins::strip_test_modules(src);
        for (i, line) in prod.lines().enumerate() {
            let axis = if line.contains(&inferred) {
                "VerbInferred"
            } else if line.contains(&categorical) {
                "Categorical"
            } else {
                continue;
            };
            // The op label is the next string literal at or after this line.
            let window: String = prod.lines().skip(i).take(3).collect::<Vec<_>>().join(" ");
            if let Some(op) = window
                .split('"')
                .nth(1)
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
            {
                out.push((op.to_string(), axis.to_string()));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Blank out `#[cfg(test)]` module bodies so a fixture cannot supply evidence.
///
/// Column-0 anchored and conservative in the SAFE direction, the same rule
/// structural check 58 uses: an over-run leaves test code in the haystack (a
/// false POSITIVE) and can never swallow production code.
fn strip_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut skipping = false;
    for line in src.lines() {
        if !skipping && line.starts_with("#[cfg(test)]") {
            skipping = true;
        }
        if skipping {
            out.push('\n');
            if line == "}" {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The three ops whose mutation status is INFERRED from the HTTP verb.
const VERB_INFERRED_OPS: [&str; 3] = ["http-fetch", "http-fetch-all", "graphql-execute"];

#[test]
fn exactly_three_gates_use_the_verb_inferred_axis() {
    let declared = declared_axes();
    assert!(
        declared.len() >= 12,
        "the axis scan found only {} gate sites — it has stopped matching and \
         is vouching for nothing: {declared:?}",
        declared.len()
    );

    let inferred: Vec<&str> = declared
        .iter()
        .filter(|(_, axis)| axis == "VerbInferred")
        .map(|(op, _)| op.as_str())
        .collect();
    let mut expected = VERB_INFERRED_OPS.to_vec();
    expected.sort_unstable();
    let mut got = inferred.clone();
    got.sort_unstable();
    assert_eq!(
        got, expected,
        "the verb-inferred axis must cover EXACTLY the three gates whose \
         mutation status is guessed from the HTTP verb. Anything else on this \
         axis is granted by `http_verb_ceiling`, which is the override an \
         operator sets to let a POST-shaped READ through — it must not also \
         grant email, NATS publish, memory writes or SQL DML."
    );
}

/// One op label, one axis. The same op is gated at more than one site (a raw
/// `wasi:http` request is an `http-fetch` too, 2026-09-25), and two sites
/// disagreeing about its axis would make the override grant it on one surface
/// and not the other. Neither test beside this one sees that: the set of
/// verb-inferred ops is unchanged by a second site flipping to categorical.
#[test]
fn every_op_has_exactly_one_axis_across_all_its_sites() {
    let mut by_op: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for (op, axis) in declared_axes() {
        by_op.entry(op).or_default().insert(axis);
    }
    for (op, axes) in by_op {
        assert_eq!(
            axes.len(),
            1,
            "`{op}` is declared on more than one axis: {axes:?}"
        );
    }
}

#[test]
fn every_categorical_op_stays_off_the_override() {
    for (op, axis) in declared_axes() {
        if VERB_INFERRED_OPS.contains(&op.as_str()) {
            continue;
        }
        assert_eq!(
            axis, "Categorical",
            "`{op}` is a categorical op — the operation IS the mutation, so \
             there is no verb inference for an override to correct. Putting it \
             on the VerbInferred axis would let `http_verb_ceiling = write` \
             grant it."
        );
    }
}

/// The override must be CARRIED from the job onto the context, not just read.
///
/// # Why this pin exists
///
/// #941 added the column, the recorded setter, the signed wire field, the
/// decision, the narrowing, the axis assignment at all fifteen gate sites and
/// nine mutations — and the worker never copied the value from the job onto
/// the context. `TalosContext::http_verb_ceiling` was initialised `None` and
/// read by the gate, so the whole axis was a NO-OP: the override was signed,
/// travelled, arrived, and was dropped.
///
/// Nine mutations missed it because a mutation can only change code that
/// exists; the defect was an ABSENT assignment. `ceiling_axis_pins`' sibling
/// tests missed it because they check which axis each gate NAMES, not whether
/// the value arrives. This pin closes that: the runtime must assign the field
/// wherever it assigns the ceiling the field modifies.
///
/// TEXTUAL, and it says so — driving it end to end needs a real job, a real
/// component and the process-global enforcement flag (check 82's objection).
#[test]
fn the_runtime_carries_the_override_wherever_it_carries_the_ceiling() {
    let src = include_str!("../runtime.rs");
    // Assembled so this pin cannot match its own source.
    let ceiling_assign = format!("context.max_write_{} =", "ceiling");
    let override_assign = format!("context.http_verb_{} =", "ceiling");

    let ceilings = src.matches(&ceiling_assign).count();
    // The RHS is part of the needle DELIBERATELY. A first draft counted the
    // assignment alone, and `context.http_verb_ceiling = None;` satisfied it
    // while restoring the exact defect — the line is present and carries
    // nothing. Measured: that mutation SURVIVED until this needle named the
    // parameter.
    let carried = format!("{override_assign} http_verb_ceiling;");
    let overrides = src.matches(carried.as_str()).count();

    assert!(
        ceilings >= 2,
        "the ceiling-assignment scan found {ceilings} sites — it has stopped \
         matching and is vouching for nothing"
    );
    assert_eq!(
        overrides, ceilings,
        "the runtime assigns `max_write_ceiling` onto the context at {ceilings} \
         site(s) but the verb-inference override at {overrides}. Every context \
         that gets a ceiling must get the override that modifies it — a context \
         missing it silently inherits, which makes the actor's `http_verb_ceiling` \
         column do nothing at all."
    );
}

/// The worker binary must hand the JOB's override to the runtime.
///
/// The pin above proves the runtime carries what it is given; this proves the
/// job's own field is what it is given. Both halves are needed: #941 had the
/// wire field populated and correct, and lost it at this hand-off.
#[test]
fn the_worker_binary_passes_the_jobs_override() {
    let src = include_str!("../../../worker/src/main.rs");
    let ceiling_arg = format!("req.max_write_{},", "ceiling");
    let override_arg = format!("req.http_verb_{},", "ceiling");

    let ceilings = src.matches(&ceiling_arg).count();
    let overrides = src.matches(&override_arg).count();
    assert!(
        !src.contains("            None,\n            req.egress_scope,"),
        "a dispatch path passes a literal `None` where the job's override \
         belongs — the field arrives on the wire and is dropped"
    );

    assert!(
        ceilings >= 2,
        "the job-argument scan found {ceilings} sites — it has stopped matching"
    );
    assert_eq!(
        overrides, ceilings,
        "the worker passes `req.max_write_ceiling` at {ceilings} dispatch \
         path(s) and `req.http_verb_ceiling` at {overrides}. A path that passes \
         one without the other drops the signed override on arrival."
    );
}
