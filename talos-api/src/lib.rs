pub(crate) mod access_check;
pub mod schema;
pub mod validation;

/// Public schema type alias. Pre-extraction lived at
/// `controller::TalosSchema`; canonical home is now this crate so
/// downstream callers (ws_auth, api_docs, controller routes) can name
/// the type without depending on the controller bin. The controller
/// keeps a re-export at its lib root for back-compat.
pub type TalosSchema =
    async_graphql::Schema<schema::QueryRoot, schema::MutationRoot, schema::SubscriptionRoot>;

/// The SDL snapshot `frontend/schema.graphql` is a copy of, byte for byte.
///
/// ONE construction, three consumers: the `dump_schema` binary that WRITES the
/// snapshot, the test below that PINS it, and any future caller that needs the
/// SDL without a runtime context. `dump_schema` used to build the schema
/// inline, so "what the binary emits" and "what a checker compares against"
/// were two expressions that could disagree.
///
/// SDL comes from the type registry alone — no `.data()` context is needed —
/// so this is a pure function of the compiled Rust types.
#[must_use]
pub fn schema_sdl() -> String {
    async_graphql::Schema::build(
        schema::QueryRoot::default(),
        schema::MutationRoot::default(),
        schema::SubscriptionRoot,
    )
    .finish()
    .sdl()
}

/// The exact command that regenerates the snapshot. Printed by the failing
/// assertion below, so the fix is in the failure message rather than in a doc
/// somebody has to find.
pub const SCHEMA_SNAPSHOT_REGEN_CMD: &str =
    "cargo run -q -p talos-api --bin dump_schema > frontend/schema.graphql && \
     (cd frontend && npm run codegen)";

#[cfg(test)]
mod schema_snapshot_tests {
    /// `frontend/schema.graphql` must equal the SDL this crate compiles to.
    ///
    /// **Why a TEST and not a structural lint**, argued rather than assumed:
    /// the comparison needs the COMPILED schema. `scripts/lint-structural.sh`
    /// has no Rust build on its default path (check 7's clippy is explicitly
    /// gated behind `TALOS_LINT_CLIPPY=1` precisely because a 60-90s build is
    /// too much for the default lint), so a lint leg here could only compare
    /// text against text — it could tell you the file exists and never that it
    /// is current, which is the gate-that-doesn't-gate shape (checks 64/65).
    /// A `#[cfg(test)] mod` inside `src/` runs in CI's ordinary unit job with
    /// no runner registration at all, so it also cannot rot the way check 64's
    /// hand-maintained `tests/`-binary lists do.
    ///
    /// **What it is guarding**, measured 2026-09-07: the snapshot was last
    /// regenerated 2026-07-27 (`aa173fa9`) and had drifted by 186 diff lines —
    /// 173 added, 13 removed. Nothing in `frontend/src` queried a drifted
    /// name, so nothing was broken; it was a snapshot that had quietly stopped
    /// being true six weeks earlier and had no way to say so.
    #[test]
    fn the_checked_in_snapshot_matches_the_compiled_schema() {
        let expected = include_str!("../../frontend/schema.graphql");
        let actual = crate::schema_sdl();
        assert_eq!(
            actual,
            expected,
            "\n\nfrontend/schema.graphql is STALE — it no longer matches the SDL \
             this crate compiles to.\n\nRegenerate with:\n\n    {}\n\n\
             (Commit BOTH frontend/schema.graphql and the regenerated \
             frontend/src/generated/* — the second is derived from the first \
             and drifts with it.)\n",
            crate::SCHEMA_SNAPSHOT_REGEN_CMD
        );
    }
}

#[cfg(test)]
mod list_complexity_schema_tests {
    use async_graphql::Schema;

    /// The controller's production ceiling
    /// (`controller/src/bootstrap/services.rs`, `.limit_complexity(5000)`).
    /// Duplicated here as a literal because the controller is a bin crate
    /// this library cannot import; if that number moves, this test says so
    /// by failing in the `limit: 10` direction (a schema-wide price change)
    /// or the `limit: 1000` direction (the ceiling was raised past the
    /// fan-out this pins).
    const PRODUCTION_COMPLEXITY_LIMIT: usize = 5000;

    fn schema() -> crate::TalosSchema {
        Schema::build(
            crate::schema::QueryRoot::default(),
            crate::schema::MutationRoot::default(),
            crate::schema::SubscriptionRoot,
        )
        .limit_complexity(PRODUCTION_COMPLEXITY_LIMIT)
        .finish()
    }

    fn is_complexity_error(errors: &[async_graphql::ServerError]) -> bool {
        errors.iter().any(|e| e.message.contains("too complex"))
    }

    /// B1-3: `workflows(limit: 1000)` with a handful of scalar children plus
    /// one nested object must be priced as 1 + 7 × 1000 and refused by the
    /// production ceiling, while the same selection at `limit: 10` (71) is
    /// admitted past complexity validation. Complexity is checked BEFORE any
    /// resolver runs, so the admitted query then fails at `require_scope`
    /// with an authentication error — that is the expected NON-complexity
    /// outcome for a request carrying no user, and it proves the query got
    /// past the ceiling without touching a database.
    #[tokio::test]
    async fn workflows_fan_out_is_priced_by_limit() {
        let schema = schema();
        let selection =
            "{ id name graphJson actorId maxConcurrentExecutions latestExecution { id } }";

        let big = schema
            .execute(format!(
                "{{ workflows(pagination: {{ limit: 1000 }}) {selection} }}"
            ))
            .await;
        assert!(
            is_complexity_error(&big.errors),
            "limit 1000 must exceed the {PRODUCTION_COMPLEXITY_LIMIT} ceiling, got {:?}",
            big.errors
        );

        let small = schema
            .execute(format!(
                "{{ workflows(pagination: {{ limit: 10 }}) {selection} }}"
            ))
            .await;
        assert!(
            !is_complexity_error(&small.errors),
            "limit 10 must pass complexity validation, got {:?}",
            small.errors
        );
        assert!(
            small
                .errors
                .iter()
                .any(|e| e.message.contains("Authentication required")),
            "the admitted query should fail at the auth gate, not before it: {:?}",
            small.errors
        );
    }

    /// The `limit`-typed (non-pagination) shape: `workflowVersions(limit: 1000)`
    /// with its eight scalar fields prices at 8001; `limit: 10` at 81.
    /// (`actorMemories` / `actorWorkflows` are deliberately NOT priced — see
    /// the comment on those resolvers — so they are not the example here.)
    #[tokio::test]
    async fn workflow_versions_fan_out_is_priced_by_limit() {
        let schema = schema();
        let wf = uuid::Uuid::nil();
        let selection = "{ id workflowId versionNumber graphJson description publishedAt \
                         publishedBy isActive }";
        let big = schema
            .execute(format!(
                "{{ workflowVersions(workflowId: \"{wf}\", limit: 1000) {selection} }}"
            ))
            .await;
        assert!(is_complexity_error(&big.errors), "{:?}", big.errors);

        let small = schema
            .execute(format!(
                "{{ workflowVersions(workflowId: \"{wf}\", limit: 10) {selection} }}"
            ))
            .await;
        assert!(!is_complexity_error(&small.errors), "{:?}", small.errors);
    }
}
