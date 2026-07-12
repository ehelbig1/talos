//! GraphQL Mutation resolvers (MutationRoot).

#[derive(async_graphql::MergedObject, Default)]
pub struct MutationRoot(
    crate::schema::actors::mutations::ActorsMutations,
    crate::schema::auth::mutations::AuthMutations,
    crate::schema::executions::mutations::ExecutionsMutations,
    crate::schema::ml::mutations::MlMutations,
    crate::schema::modules::mutations::ModulesMutations,
    crate::schema::organizations::mutations::OrganizationsMutations,
    crate::schema::platform::mutations::PlatformMutations,
    crate::schema::secrets::mutations::SecretsMutations,
    crate::schema::security::mutations::SecurityMutations,
    crate::schema::webhooks::mutations::WebhooksMutations,
    crate::schema::workflows::mutations::WorkflowsMutations,
);
