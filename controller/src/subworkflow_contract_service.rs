// Sub-workflow contract testing service moved to the
// `talos-subworkflow-contract` workspace crate. The pre-extraction
// signature took `state: &McpState`; the new signature takes
// `deps: &ContractServiceDeps`, a narrow container for the four
// McpState fields the service actually uses (nats_client,
// secrets_manager, registry, actor_repo). See mcp/workflows.rs
// `handle_test_subworkflow_contract` for the call-site adapter.
#![allow(dead_code, unused_imports)]
pub use talos_subworkflow_contract::*;
