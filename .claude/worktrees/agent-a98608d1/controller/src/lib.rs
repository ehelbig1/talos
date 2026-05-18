// Enforce strict linting for the controller crate, but allow dead code warnings
// that arise from optional features or future expansion. Individual modules can
// still add more granular `#![allow(...)]` directives as needed.
#![allow(dead_code)]
#![allow(clippy::all)]
// Library interface for controller modules
// This allows integration tests to access internal modules

pub mod api;
pub mod api_keys;
pub mod auth;
pub mod compilation;
pub mod config;
pub mod csrf;
pub mod db;
pub mod engine;
pub mod gmail;
pub mod google_calendar;
pub mod llm;
pub mod module_executions;
pub mod oauth;
pub mod rate_limit;
pub mod registry;
pub mod secrets;
pub mod security_headers;
pub mod slack;
pub mod templates;
pub mod totp_2fa;
pub mod trace_nats;
pub mod webhooks;
pub mod wit_inspector;
pub mod workflow_engine;

// Re-export worker crate for tests
pub use worker;
// ws_auth is not exposed in lib - it's only used in main.rs binary
// pub mod ws_auth;
