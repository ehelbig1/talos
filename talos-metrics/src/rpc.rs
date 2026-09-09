//! The signed-RPC data plane's instrument vocabulary: one table from which
//! the label sets, the pre-seed loop and the log-level partition all derive.
//!
//! # Why a table and not two `&'static str` parameters
//!
//! `talos_rpc_subscribers::kernel::record_rpc_metric` took
//! `subject: &'static str` and `outcome: &'static str`. Every argument at
//! every one of its 41 call sites was in fact a literal or a `&'static str`
//! bound by an exhaustive `match` over a closed error enum — so the label sets
//! were closed by CONVENTION. `&'static str` also accepts
//! `Box::leak(caller_supplied.into())`, and a caller-derived label value on a
//! metric reachable by anything that can publish to a NATS subject is an
//! unbounded-cardinality DoS surface. `actor_id` is a LOG FIELD on that
//! function and must never become a label for the same reason.
//!
//! With seven subjects and eighteen outcomes an enum is affordable, so the
//! sets are closed BY THE COMPILER here: a label value that is not in this
//! file is not expressible at a call site.
//!
//! # Why the subject strings are duplicated
//!
//! They are `pub const`s in `talos-memory`
//! (`memory_rpc::SUBJECT`, `graph_rpc::SUBJECT`, …), but `talos-memory`
//! depends on this crate's consumers and pulls in sqlx, the crypto stack and
//! the whole memory service; importing it here to read seven strings would
//! invert the layering. So they are duplicated and pinned equal to their
//! originals by `the_subject_table_matches_the_wire_constants` in
//! `talos-rpc-subscribers`, where both are visible. Same shape, same reason,
//! as [`crate::RPC_WRITE_CEILING_SUBJECTS`] (#760).

/// What an outcome means to an OPERATOR, which is a different question from
/// what it means to the caller.
///
/// This is the ONE home the `talos_rpc` log level rests on, the `class` label
/// on [`crate::TalosMetrics::rpc_calls_total`], and therefore the one home a
/// future alert selector rests on too. Modelled on
/// `talos_task_supervision::TaskExit::is_finding` (#780): the question is not
/// "did the platform fail" but "should someone look at this".
///
/// Before this existed the partition was binary — `outcome == "ok"` was
/// `debug!` and EVERYTHING else was `warn!` — so a designed pre-promotion
/// state produced 53% of the controller's entire WARN volume, hourly,
/// forever. That is check 69's harm: a level that fires forever on a healthy
/// fleet trains operators to ignore that level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RpcOutcomeClass {
    /// The call was answered. High volume, routine, uninteresting on its own.
    Served,
    /// The platform answered CORRECTLY by declining: a policy refusal, a
    /// designed lifecycle state, a configured cap, or a caller error the
    /// caller was told about. A healthy fleet produces these and no operator
    /// action follows from one of them.
    Declined,
    /// Someone should look: either the platform could not serve the call, or
    /// the call should not have arrived in the shape it did.
    Finding,
}

impl RpcOutcomeClass {
    /// The one predicate. Named for #780's precedent so the two read alike.
    #[must_use]
    pub const fn is_finding(self) -> bool {
        matches!(self, Self::Finding)
    }

    /// The `class` label value.
    ///
    /// Three compile-time values, and `class` is a pure function of `outcome`,
    /// so this label adds NO series: every `(subject, outcome)` has exactly
    /// one class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Declined => "declined",
            Self::Finding => "finding",
        }
    }

    /// Every variant, for the tests and for anything that must enumerate the
    /// partition.
    pub const ALL: &'static [Self] = &[Self::Served, Self::Declined, Self::Finding];
}

macro_rules! rpc_outcome_table {
    ($( $(#[$m:meta])* $variant:ident = $label:literal => $class:ident ; )+) => {
        /// The complete, closed set of `outcome` label values on the RPC
        /// instrument — and, because the same value is the `outcome` field of
        /// the `talos_rpc` log line, the closed set of spellings an operator's
        /// existing log filters can see.
        ///
        /// Each label is byte-identical to the string literal the call site
        /// passed before this enum existed, so no log filter or saved query
        /// breaks.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum RpcOutcome {
            $( $(#[$m])* $variant, )+
        }

        impl RpcOutcome {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The label value / log field.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $label, )+ }
            }

            /// What this outcome means to an operator. See
            /// [`RpcOutcomeClass`]; the per-variant argument is on each
            /// variant's own doc comment.
            #[must_use]
            pub const fn class(self) -> RpcOutcomeClass {
                match self { $( Self::$variant => RpcOutcomeClass::$class, )+ }
            }
        }
    };
}

rpc_outcome_table! {
    /// The call was served.
    Ok = "ok" => Served;

    // ── Declined ────────────────────────────────────────────────────────
    /// The caller sent something malformed. A caller error, and the caller is
    /// told — identically for every reason, since the reply is deliberately
    /// reason-blind (#754). The calling module's own execution fails through
    /// the ordinary execution-failure channel, so the operator is not blind.
    Invalid = "invalid" => Declined;
    /// The key / model / row is not there. `agent_memory::get` on a key that
    /// has never been written is the normal "no memory yet" path.
    NotFound = "not_found" => Declined;
    /// `MlRpcError::NotPromoted` — "Model exists but has no promoted version
    /// to serve." A DESIGNED position on the documented lifecycle ladder
    /// (`llm_only -> shadow -> hybrid -> fast_primary`): below `hybrid`,
    /// `talos_ml::serve::state_serves_production` is false and every
    /// prediction falls back to the LLM by construction.
    /// `talos_ml::loop_health::gold_promoted_serving_note` is the
    /// purpose-built operator surface for exactly this fact.
    NotPromoted = "not_promoted" => Declined;
    /// A configured size cap refused the payload or the result.
    TooLarge = "too_large" => Declined;
    /// A configured quota refused the write (per-value size on `memory.op`,
    /// `MAX_ROWS_PER_INTEGRATION_USER` on `integration_state.op`).
    StorageFull = "storage_full" => Declined;
    /// The sandbox SQL validator refused a statement CLASS that is never
    /// permitted (DDL, role changes, …).
    AlwaysBlocked = "always_blocked" => Declined;
    /// The sandbox SQL function deny-list refused an expression.
    DisallowedFunction = "disallowed_function" => Declined;
    /// The statement type is outside this caller's allowlist.
    StatementNotPermitted = "statement_not_permitted" => Declined;

    // ── Finding ─────────────────────────────────────────────────────────
    /// Signature / freshness / nonce rejection at admission. NOT a designed
    /// state: on a transport where every legitimate sender holds
    /// `WORKER_SHARED_KEY`, this means clock skew, a half-rotated key, or a
    /// sender that should not be there. Deliberately NOT alerted on (see the
    /// counter's HELP) — it has no baseline yet — but it stays loud.
    Unauthorized = "unauthorized" => Finding;
    /// The replay-nonce cache refused a duplicate. A retry storm or a probe,
    /// not a designed state.
    Replay = "replay" => Finding;
    /// The controller refused an actor-attributed mutation on the per-actor
    /// write ceiling. #760 already decided this question in this direction:
    /// its counter's HELP calls a non-zero value "a FLEET CONFIGURATION
    /// signal" — the sending worker did not run its own gate — and ships a
    /// `warning` alert on it.
    WriteCeiling = "write_ceiling" => Finding;
    /// The semaphore queue outran the caller's own deadline, so the work was
    /// skipped rather than burned into a dead reply inbox. This IS the
    /// saturation signal for a subject (see [`crate::TalosMetrics::rpc_calls_total`]'s
    /// HELP, and D8 in the package notes for why no separate queue histogram
    /// ships).
    StaleDeadline = "stale_deadline" => Finding;
    /// `MlRpcError::NotAvailable` — "Promoted backend can't serve (dataset
    /// gone, unsupported backend, embedder down) — the RFC's loud lifecycle
    /// failure mode." The enum's own documentation asks for loud.
    NotAvailable = "not_available" => Finding;
    /// A SQL statement that passed every gate then failed at the database.
    ///
    /// **Two producers with opposite meanings, and this classification is the
    /// conservative one.** On `talos.database.query` it is the GUEST's SQL
    /// failing — a caller error. On `talos.state.write` it is the
    /// CONTROLLER's own `execution_state` UPSERT/DELETE failing, which is
    /// silent to the guest by contract, and MCP-733 deliberately made it WARN
    /// ("so SIEM / dashboard alerting can fire on sustained query_error
    /// outcomes"). One label cannot say both; classifying it `Declined` would
    /// silence MCP-733's decision. The counter separates them by `subject`.
    QueryError = "query_error" => Finding;
    /// The database was unreachable, or the connection could not be prepared.
    ConnectionFailed = "connection_failed" => Finding;
    /// The platform did not answer in time.
    Timeout = "timeout" => Finding;
    /// The platform failed for a reason it could not classify.
    Internal = "internal" => Finding;
}

macro_rules! rpc_subject_table {
    ($( $(#[$m:meta])* $variant:ident = $wire:literal => [ $( $out:ident ),+ $(,)? ] ; )+) => {
        /// The complete, closed set of `subject` label values: the seven NATS
        /// subjects the controller serves for credential-free workers.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum RpcSubject {
            $( $(#[$m])* $variant, )+
        }

        impl RpcSubject {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The NATS subject, byte-identical to the `pub const` in
            /// `talos-memory` that the subscriber actually subscribes to.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $wire, )+ }
            }

            /// The outcomes THIS subject's subscriber can pass to
            /// [`crate::record_rpc_call`] — its own literals plus every arm of
            /// its own terminal `match` over its own error enum.
            ///
            /// This is the pre-seed set, and it is deliberately NOT the cross
            /// product: 64 pairs against 7 × 18 = 126. Seeding the product
            /// would seed 62 combinations no call site can reach, which is
            /// check 58's own defect (a series nothing can move reads as a
            /// wired signal that does not exist).
            #[must_use]
            pub const fn outcomes(self) -> &'static [RpcOutcome] {
                match self {
                    $( Self::$variant => &[ $( RpcOutcome::$out, )+ ], )+
                }
            }
        }
    };
}

rpc_subject_table! {
    /// Neo4j graph-RAG search. `graph_rpc::GraphSearchRequest`.
    GraphSearch = "talos.graph.search" => [
        Ok, Invalid, Unauthorized, Replay, NotAvailable, Timeout, Internal,
    ];
    /// RFC 0011 model inference. `ml_rpc::MlPredictRequest`.
    MlPredict = "talos.ml.predict" => [
        Ok, Invalid, Unauthorized, Replay, NotFound, NotPromoted, NotAvailable,
        StaleDeadline, Timeout, Internal,
    ];
    /// Human-correction few-shot anchors for the LLM teacher leg.
    /// `ml_rpc::MlFewShotRequest`.
    MlFewShot = "talos.ml.fewshot" => [
        Ok, Invalid, Unauthorized, Replay, NotFound, NotPromoted, NotAvailable,
        StaleDeadline, Timeout, Internal,
    ];
    /// All actor-memory access. `memory_rpc::MemoryOp`.
    MemoryOp = "talos.memory.op" => [
        Ok, Invalid, Unauthorized, Replay, NotFound, StorageFull, WriteCeiling,
        Timeout, Internal,
    ];
    /// Sandbox SQL via the `database` WIT.
    /// `database_rpc::DatabaseRpcRequest`.
    DatabaseQuery = "talos.database.query" => [
        Ok, Invalid, Unauthorized, Replay, AlwaysBlocked, DisallowedFunction,
        StatementNotPermitted, WriteCeiling, TooLarge, QueryError,
        ConnectionFailed, Timeout,
    ];
    /// `execution_state` durability, fire-and-forget.
    /// `state_rpc::StateWriteRequest`.
    StateWrite = "talos.state.write" => [
        Ok, Invalid, Unauthorized, Replay, TooLarge, QueryError, Timeout,
    ];
    /// Per-user integration watch state. `integration_state_rpc::IntegrationOp`.
    IntegrationStateOp = "talos.integration_state.op" => [
        Ok, Invalid, Unauthorized, Replay, NotFound, StorageFull, WriteCeiling,
        Timeout, Internal,
    ];
}

/// Every `(subject, outcome)` pair a call site can pass — the pre-seed set,
/// and the ONLY set of label combinations the RPC counter may ever export.
///
/// The pre-seed loop in [`crate::TalosMetrics::new`] IS this iterator, so a
/// pair the loop misses is not expressible: there is no hand-maintained
/// parallel list to rot (#778's `BackgroundTask` shape).
pub fn seeded_pairs() -> impl Iterator<Item = (RpcSubject, RpcOutcome)> {
    RpcSubject::ALL
        .iter()
        .flat_map(|s| s.outcomes().iter().map(move |o| (*s, *o)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// TRIPWIRE. A table that has become empty, or whose two halves have
    /// stopped agreeing, must fail LOUDLY rather than seed nothing — a check
    /// that matches nothing is a green tick over nothing (checks 64/65).
    #[test]
    fn the_table_is_not_empty_and_the_counts_are_pinned() {
        assert_eq!(RpcSubject::ALL.len(), 7, "subject count changed");
        assert_eq!(RpcOutcome::ALL.len(), 18, "outcome vocabulary changed");
        assert_eq!(
            seeded_pairs().count(),
            64,
            "the reachable (subject, outcome) set changed; re-derive it from \
             talos-rpc-subscribers/src/lib.rs (the_declared_table_matches_the_source \
             does this mechanically) before changing this number"
        );
        // The whole point of the per-subject table: it is NOT the product.
        assert!(
            seeded_pairs().count() < RpcSubject::ALL.len() * RpcOutcome::ALL.len(),
            "the per-subject table has degenerated into the cross product, which \
             seeds combinations no call site can reach"
        );
    }

    /// Every declared outcome is reachable from at least one subject.
    /// A variant no subject lists is a label value nothing can ever emit.
    #[test]
    fn every_outcome_is_reachable_from_some_subject() {
        let reachable: HashSet<RpcOutcome> = seeded_pairs().map(|(_, o)| o).collect();
        let orphans: Vec<&str> = RpcOutcome::ALL
            .iter()
            .filter(|o| !reachable.contains(o))
            .map(|o| o.as_str())
            .collect();
        assert!(
            orphans.is_empty(),
            "outcomes no subject can produce: {orphans:?}"
        );
    }

    /// Labels are unique, so two variants cannot silently share a series.
    #[test]
    fn label_values_are_distinct() {
        let outs: HashSet<&str> = RpcOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(outs.len(), RpcOutcome::ALL.len());
        let subs: HashSet<&str> = RpcSubject::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(subs.len(), RpcSubject::ALL.len());
        let classes: HashSet<&str> = RpcOutcomeClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(classes.len(), 3);
    }

    /// The partition, pinned by NAME rather than by count, so a reclassified
    /// outcome fails here and has to be argued rather than slipping through.
    ///
    /// The direction that matters is the QUIET one: an outcome moved out of
    /// `Finding` stops being a `warn!` and stops matching the `class="finding"`
    /// alert, in one edit, silently.
    #[test]
    fn the_partition_is_the_one_that_was_argued() {
        let of = |c: RpcOutcomeClass| {
            let mut v: Vec<&str> = RpcOutcome::ALL
                .iter()
                .filter(|o| o.class() == c)
                .map(|o| o.as_str())
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(of(RpcOutcomeClass::Served), vec!["ok"]);
        assert_eq!(
            of(RpcOutcomeClass::Declined),
            vec![
                "always_blocked",
                "disallowed_function",
                "invalid",
                "not_found",
                "not_promoted",
                "statement_not_permitted",
                "storage_full",
                "too_large",
            ]
        );
        assert_eq!(
            of(RpcOutcomeClass::Finding),
            vec![
                "connection_failed",
                "internal",
                "not_available",
                "query_error",
                "replay",
                "stale_deadline",
                "timeout",
                "unauthorized",
                "write_ceiling",
            ]
        );
        // `is_finding` is the ONE predicate; it must agree with the class.
        for o in RpcOutcome::ALL {
            assert_eq!(
                o.class().is_finding(),
                o.class() == RpcOutcomeClass::Finding,
                "{}",
                o.as_str()
            );
        }
    }

    /// #760's three ceiling-gated subjects are exactly the subjects whose
    /// table lists `write_ceiling`. Two lists in one crate that disagree
    /// about which subjects can refuse on the ceiling is the drift this pins.
    #[test]
    fn write_ceiling_subjects_agree_with_the_760_seed_list() {
        let mut from_table: Vec<&str> = RpcSubject::ALL
            .iter()
            .filter(|s| s.outcomes().contains(&RpcOutcome::WriteCeiling))
            .map(|s| s.as_str())
            .collect();
        from_table.sort_unstable();
        let mut from_760 = crate::RPC_WRITE_CEILING_SUBJECTS.to_vec();
        from_760.sort_unstable();
        assert_eq!(from_table, from_760);
    }
}
