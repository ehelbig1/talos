//! The MCP `tools/call` instrument's outcome vocabulary: one table from which
//! the label values, the class partition and the pins all derive.
//!
//! # Why a table, and why six values rather than four
//!
//! #786 shipped four — `ok | error | refused | unknown_tool` — with the split
//! that mattered to it (`-32602` "the caller can fix it" vs everything else)
//! and everything else folded into `error`. Measured on this tree the
//! remainder is not one thing: of the 648 `mcp_error` sites at `-32000`,
//! roughly 250 are REFUSALS ("Workflow not found or access denied" alone is
//! 123 of them) and the rest are failures. Eleven of the twelve `-32601`
//! sites are platform-admin refusals recorded as `unknown_tool`; seven of the
//! fifteen `-32603` sites are capability-ceiling refusals recorded as
//! `error`. The first thing this instrument ever recorded on the dev fleet
//! was a `-32003` "requires admin capability" refusal, counted `error` in
//! 33 µs — the platform's authorization working exactly as designed, filed
//! as a server fault.
//!
//! So `denied` and `not_found` join the set. Both are the CALLER being told
//! no, and both class as [`crate::OutcomeClass::Declined`]; they stay
//! separate OUTCOMES because "the caller asked for a row that is not there"
//! and "the caller was refused" are different operator readings, exactly as
//! `RpcOutcome::{NotFound, Unauthorized}` are on the RPC surface.
//!
//! The four existing spellings are byte-identical to what #786 shipped, so
//! no log filter or saved query breaks — [`crate::rpc`]'s rule, for the same
//! reason.
//!
//! # Cardinality
//!
//! `talos_mcp_tool_calls_total` is NOT pre-seeded and deliberately so: the
//! product is `tools × outcomes` (~320 × 6) and almost none of those pairs is
//! reachable — a tool that takes no arguments cannot answer `refused` —
//! so seeding it would mint ~1900 series nothing can move, which is check
//! 58's own defect. `class` adds NO series because it is a pure function of
//! `outcome`; `the_class_label_adds_no_series` verifies that rather than
//! assuming it.

use crate::OutcomeClass;

macro_rules! mcp_outcome_table {
    ($( $(#[$m:meta])* $variant:ident = $label:literal => $class:ident ; )+) => {
        /// The complete, closed set of `outcome` label values on the MCP
        /// `tools/call` instrument — and, because the same value is the
        /// `outcome` field of the `talos_mcp` log line, the closed set of
        /// spellings an operator's existing log filters can see.
        ///
        /// An ENUM rather than a `&str` so the label set is closed BY THE
        /// COMPILER: a seventh outcome cannot be spelled at a call site
        /// without being added here, where its class — and therefore its
        /// effect on anything selecting on `class` — has to be stated.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum McpToolOutcome {
            $( $(#[$m])* $variant, )+
        }

        impl McpToolOutcome {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The label value / log field.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $label, )+ }
            }

            /// What this outcome means to an operator. See
            /// [`OutcomeClass`]; the per-variant argument is on each
            /// variant's own doc comment.
            #[must_use]
            pub const fn class(self) -> OutcomeClass {
                match self { $( Self::$variant => OutcomeClass::$class, )+ }
            }
        }
    };
}

mcp_outcome_table! {
    /// A result with no `isError`. The call was served.
    Ok = "ok" => Served;

    // ── Declined ────────────────────────────────────────────────────────
    /// `-32602`: the request itself is wrong — a missing argument, an
    /// unparseable uuid, a value outside an enum. The caller can fix it.
    /// #786's own argument for splitting this off: "folding them into `error`
    /// would make a client looping on a typo indistinguishable from an
    /// outage." SPELLING PRESERVED from #786.
    Refused = "refused" => Declined;
    /// `-32601` from the ONE site that means it: no dispatch arm claimed the
    /// name. SPELLING PRESERVED from #786 — but note that eleven of the
    /// twelve `-32601` sites on this tree are platform-admin refusals, which
    /// now say `talos_mcp::McpErrorKind::Denied` explicitly and land on
    /// `denied` instead.
    UnknownTool = "unknown_tool" => Declined;
    /// The platform refused a WELL-FORMED request: authorization, a
    /// capability ceiling, org membership, a lifecycle or policy state, or
    /// the deliberately collapsed "not found or access denied".
    ///
    /// The line against `refused` is the request, not the outcome:
    /// `refused` means *your arguments are wrong*, `denied` means *your
    /// arguments were fine and the answer is no*. A burst of `denied` is a
    /// security signal; a burst of `refused` is a client bug; folded into
    /// `error` both were an outage.
    Denied = "denied" => Declined;
    /// The named row is not there and no tenancy question is attached. Its
    /// own outcome, but `Declined` like the rest: `RpcOutcome::NotFound =>
    /// Declined` (#787) took this decision on the ground that a `get` on a
    /// key never written is the normal path, and a `ml_get_model_card` for a
    /// model nobody has created yet is the same shape.
    NotFound = "not_found" => Declined;

    // ── Finding ─────────────────────────────────────────────────────────
    /// The platform could not serve the call — or nothing classified it.
    ///
    /// The fallback is deliberately the LOUD one, and it is why this package
    /// leaves the unclassified remainder honest rather than optimistic: a
    /// site nobody has read is not evidence that the caller was at fault.
    /// SPELLING PRESERVED from #786.
    Error = "error" => Finding;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// TRIPWIRE. A table that has become empty must fail LOUDLY rather than
    /// pin nothing — a check that matches nothing is a green tick over
    /// nothing (checks 64/65).
    #[test]
    fn the_table_is_not_empty_and_the_count_is_pinned() {
        assert_eq!(
            McpToolOutcome::ALL.len(),
            6,
            "the MCP outcome vocabulary changed; state the new value's class \
             and update the partition pin below"
        );
    }

    /// #786's four spellings must not move: they are already in this fleet's
    /// container logs and in any saved query built on them.
    #[test]
    fn the_four_original_spellings_are_unchanged() {
        assert_eq!(McpToolOutcome::Ok.as_str(), "ok");
        assert_eq!(McpToolOutcome::Error.as_str(), "error");
        assert_eq!(McpToolOutcome::Refused.as_str(), "refused");
        assert_eq!(McpToolOutcome::UnknownTool.as_str(), "unknown_tool");
    }

    #[test]
    fn label_values_are_distinct() {
        let outs: HashSet<&str> = McpToolOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(outs.len(), McpToolOutcome::ALL.len());
    }

    /// The partition, pinned by NAME rather than by count, so a reclassified
    /// outcome fails here and has to be argued rather than slipping through.
    ///
    /// The direction that matters is the QUIET one: an outcome moved OUT of
    /// `Finding` stops matching a `class="finding"` selector in one edit; an
    /// outcome moved IN makes a healthy fleet's refusals read as faults,
    /// which is the state this package exists to leave.
    #[test]
    fn the_partition_is_the_one_that_was_argued() {
        let of = |c: OutcomeClass| {
            let mut v: Vec<&str> = McpToolOutcome::ALL
                .iter()
                .filter(|o| o.class() == c)
                .map(|o| o.as_str())
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(of(OutcomeClass::Served), vec!["ok"]);
        assert_eq!(
            of(OutcomeClass::Declined),
            vec!["denied", "not_found", "refused", "unknown_tool"]
        );
        assert_eq!(of(OutcomeClass::Finding), vec!["error"]);
        for o in McpToolOutcome::ALL {
            assert_eq!(
                o.class().is_finding(),
                o.class() == OutcomeClass::Finding,
                "{}",
                o.as_str()
            );
        }
    }

    /// VERIFIED, not assumed (the brief's instruction, and #787's omission):
    /// `class` is a pure function of `outcome`, so adding it as a third label
    /// multiplies the series count by exactly one.
    #[test]
    fn the_class_label_adds_no_series() {
        let pairs: HashSet<(&str, &str)> = McpToolOutcome::ALL
            .iter()
            .map(|o| (o.as_str(), o.class().as_str()))
            .collect();
        assert_eq!(
            pairs.len(),
            McpToolOutcome::ALL.len(),
            "an outcome maps to more than one class, so (tool, outcome, class) \
             would carry more series than (tool, outcome)"
        );
    }

    /// The two surfaces share the class TYPE, so the three spellings cannot
    /// drift. This asserts the sharing rather than the spellings, which
    /// `outcome_class`' own tests own.
    #[test]
    fn the_class_spellings_are_the_rpc_surfaces_own() {
        for o in McpToolOutcome::ALL {
            assert!(
                OutcomeClass::ALL.contains(&o.class()),
                "{} classed outside the shared partition",
                o.as_str()
            );
        }
    }
}
