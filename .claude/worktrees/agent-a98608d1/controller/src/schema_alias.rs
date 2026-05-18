// Public schema alias
use crate::api::schema::{MutationRoot, QueryRoot, SubscriptionRoot};
use async_graphql::Schema;

pub type TalosSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;
