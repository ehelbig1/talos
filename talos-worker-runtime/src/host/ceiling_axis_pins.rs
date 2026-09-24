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

    let files: [&str; 9] = [
        include_str!("http.rs"),
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
