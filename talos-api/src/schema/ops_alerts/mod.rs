//! GraphQL surface for the `ops_alerts` triage domain — the operator-facing
//! read/act UI (list active alerts + digest rollup; ack / resolve / correct).
//!
//! Every resolver is owner-scoped by the session `user_id` (never a query
//! argument) and delegates to `talos_ops_alerts_repository::OpsAlertRepository`
//! — the SAME repository the MCP triage handlers use, so the two protocol
//! surfaces share one implementation of the tenancy/never-clobber invariants
//! and cannot drift. No SQL lives here (lint 50; the repository owns it).

pub mod mutations;
pub mod queries;
