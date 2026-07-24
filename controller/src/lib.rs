// Library interface for controller modules — Clippy lints enforced crate-wide.
//
// Note: the crate-wide `#![allow(dead_code)]` that used to live here was
// removed during the May-2026 post-extraction cleanup. After 92 talos-*
// crates absorbed the implementation, controller/src/ is now ~80 thin
// re-export shims plus main.rs (~5k LoC); a `cargo check --all-targets`
// reports zero dead_code warnings. If a re-introduction of legitimately-
// dead-but-needed-for-tests code becomes necessary, prefer a targeted
// `#[allow(dead_code)]` on the specific item rather than re-instating
// the crate-wide allow — the latter masks real dead code from clippy.
//
// async-graphql 7.x macro expansion under cargo test exceeds the default
// 128-deep query layout walk on the talos-api MutationRoot. Bump to 256;
// the bin target compiles fine without this since it never type-walks the
// schema's metadata recursively.
#![recursion_limit = "256"]

pub mod actor_memory_service;
pub mod actor_policies;
pub mod actor_repository;
pub(crate) mod actor_scaffold_service;
pub(crate) mod advanced_repository;
pub(crate) mod analytics_repository;
pub mod api;
pub mod api_keys;
pub mod atlassian;
pub mod auth;
pub mod capability_downgrade;
pub mod compilation;
pub mod config;
pub mod cost_attribution;
pub mod csrf;
pub mod db;
pub mod dlp;
pub mod engine;
pub(crate) mod execution_repository;
pub mod gmail;
pub mod google_calendar;
pub mod graph_rag;
pub mod idempotency;
pub mod integration_state_service;
pub mod integrations;
pub mod llm;
pub mod mcp;
pub mod memory_crypto;
pub mod metrics;
pub mod module_executions;
pub mod module_payload_encryption;
pub mod module_repository;
pub mod module_templates;
pub mod node_cache;
pub mod oauth;
pub mod organizations;
pub mod rate_limit;
pub mod registry;
pub mod replay_diff;
pub mod request_id;
pub mod retry_intelligence;
pub(crate) mod schedule_repository;
pub mod scheduler;
pub mod secrets;
pub mod security_headers;
pub mod slack;
pub mod subworkflow_contract_service;
pub(crate) mod system_repository;
pub mod templates;
pub(crate) mod text_util;
pub mod totp_2fa;
pub mod trace_nats;
pub(crate) mod webhook_repository;
pub mod webhooks;
pub mod wit_inspector;
pub mod worker_manager;
pub(crate) mod workflow_authorization;
pub(crate) mod workflow_creation_helpers;
pub(crate) mod workflow_repository;
pub mod workflow_signing;
pub mod workflow_validation;
pub mod workflow_versions;
pub mod ws_auth;
pub mod yaml_workflows;

// Re-export the worker runtime crate for tests (was `pub use worker;`
// before the July-2026 lib extraction — controller consumes the library
// crate, never the deployable worker bin).
pub use talos_worker_runtime;

/// Public schema type alias re-exported from the `talos-api` crate.
/// Canonical home is `talos_api::TalosSchema`; this controller-side
/// re-export preserves the historical `controller::TalosSchema` path.
pub use talos_api::TalosSchema;
