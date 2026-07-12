//! Print the controller's GraphQL SDL to stdout.
//!
//! Refreshes the checked-in `frontend/schema.graphql` snapshot that
//! graphql-codegen reads offline (see `frontend/codegen.yml`). SDL is
//! derived from the type registry alone, so no runtime `.data()` context
//! is needed. Run from the repo root:
//!
//! ```sh
//! cargo run -p talos-api --bin dump_schema > frontend/schema.graphql
//! ```

fn main() {
    let schema = async_graphql::Schema::build(
        talos_api::schema::QueryRoot::default(),
        talos_api::schema::MutationRoot::default(),
        talos_api::schema::SubscriptionRoot,
    )
    .finish();
    print!("{}", schema.sdl());
}
