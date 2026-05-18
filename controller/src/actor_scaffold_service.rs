// Actor scaffolding service moved to the `talos-actor-scaffold` workspace
// crate. The pre-extraction signature took `state: &McpState`; the new
// signature takes `deps: &ScaffoldServiceDeps`, a narrow container for
// the four McpState fields the service actually uses (db_pool, actor_repo,
// module_repo, workflow_repo). See `mcp/actor.rs::handle_scaffold_actor`
// for the call-site adapter.
#![allow(dead_code, unused_imports)]
pub use talos_actor_scaffold::*;
