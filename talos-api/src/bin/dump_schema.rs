//! Print the controller's GraphQL SDL to stdout.
//!
//! Refreshes the checked-in `frontend/schema.graphql` snapshot that
//! graphql-codegen reads offline (see `frontend/codegen.yml`). Run from the
//! repo root:
//!
//! ```sh
//! cargo run -q -p talos-api --bin dump_schema > frontend/schema.graphql
//! (cd frontend && npm run codegen)
//! ```
//!
//! The schema is built by `talos_api::schema_sdl` and NOT inline here, so the
//! bytes this binary emits are the same bytes
//! `schema_snapshot_tests::the_checked_in_snapshot_matches_the_compiled_schema`
//! compares the snapshot against. Two expressions for "the schema" is how the
//! writer and the checker drift apart.

fn main() {
    print!("{}", talos_api::schema_sdl());
}
