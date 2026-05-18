//! Re-export shim for the extracted `talos-mcp-handlers` crate.
//!
//! All 27 MCP handler files (actor, advanced, alerts, analytics,
//! auth, capability_worlds, configuration, executions, graph,
//! knowledge_graph, modules, ollama, platform, resources, sandbox,
//! schedules, schemas, search, secrets, types, utils, versions,
//! webhooks, workflows) plus McpState, create_router, the per-agent
//! / per-user rate limiters, and PROCESS_START_TIME live in
//! `talos-mcp-handlers`. This shim preserves the existing
//! `crate::mcp::*` import path used by `controller::main` (router
//! construction + state wiring), `controller::ws_auth`, and the
//! GraphQL `api::schema::*` tree
//! (post-decoupling, only re-exported helpers like spawn_log_action
//! / world_rank are still consumed across the boundary, both via
//! their canonical homes — see commit 73cfdf8).

#![allow(unused_imports)]

pub use talos_mcp_handlers::*;

pub mod actor {
    pub use talos_mcp_handlers::actor::*;
}
pub mod advanced {
    pub use talos_mcp_handlers::advanced::*;
}
pub mod alerts {
    pub use talos_mcp_handlers::alerts::*;
}
pub mod analytics {
    pub use talos_mcp_handlers::analytics::*;
}
pub mod auth {
    pub use talos_mcp_handlers::auth::*;
}
pub mod capability_worlds {
    pub use talos_mcp_handlers::capability_worlds::*;
}
pub mod configuration {
    pub use talos_mcp_handlers::configuration::*;
}
pub mod executions {
    pub use talos_mcp_handlers::executions::*;
}
pub mod graph {
    pub use talos_mcp_handlers::graph::*;
}
pub mod knowledge_graph {
    pub use talos_mcp_handlers::knowledge_graph::*;
}
pub mod modules {
    pub use talos_mcp_handlers::modules::*;
}
pub mod ollama {
    pub use talos_mcp_handlers::ollama::*;
}
pub mod platform {
    pub use talos_mcp_handlers::platform::*;
}
pub mod resources {
    pub use talos_mcp_handlers::resources::*;
}
pub mod sandbox {
    pub use talos_mcp_handlers::sandbox::*;
}
pub mod schedules {
    pub use talos_mcp_handlers::schedules::*;
}
pub mod schemas {
    pub use talos_mcp_handlers::schemas::*;
}
pub mod search {
    pub use talos_mcp_handlers::search::*;
}
pub mod secrets {
    pub use talos_mcp_handlers::secrets::*;
}
pub mod types {
    pub use talos_mcp_handlers::types::*;
}
pub mod utils {
    pub use talos_mcp_handlers::utils::*;
}
pub mod versions {
    pub use talos_mcp_handlers::versions::*;
}
pub mod webhooks {
    pub use talos_mcp_handlers::webhooks::*;
}
pub mod workflows {
    pub use talos_mcp_handlers::workflows::*;
}
