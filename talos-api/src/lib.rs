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
