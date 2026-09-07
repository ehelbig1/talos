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
