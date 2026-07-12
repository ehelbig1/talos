//! GraphQL surface for the RFC 0011 ML lifecycle — the human-in-the-loop
//! model-review UI (list models needing review + resolve disagreements).
//!
//! Every resolver is owner-scoped by the session `user_id` (never a query
//! argument) and delegates to `talos_ml` services — the SAME
//! `LifecycleService` / `ModelRegistry` / shared `resolve_disagreement`
//! flow the MCP handlers use, so the two protocol surfaces share one
//! implementation of the tenancy invariants and cannot drift.

pub mod mutations;
pub mod queries;
