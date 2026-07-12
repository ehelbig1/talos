//! GraphQL Query resolvers (QueryRoot).

#[derive(async_graphql::MergedObject, Default)]
pub struct QueryRoot(
    crate::schema::actors::queries::ActorsQueries,
    crate::schema::auth::queries::AuthQueries,
    crate::schema::ml::queries::MlQueries,
    crate::schema::modules::queries::ModulesQueries,
    crate::schema::organizations::queries::OrganizationsQueries,
    crate::schema::platform::queries::PlatformQueries,
    crate::schema::secrets::queries::SecretsQueries,
    crate::schema::security::queries::SecurityQueries,
    crate::schema::webhooks::queries::WebhooksQueries,
    crate::schema::workflows::queries::WorkflowsQueries,
);
