//! Plaid integration — read-only access to a user's own financial accounts.
//!
//! # Shape, and why
//!
//! This is a CONTROLLER-side crate, not a WASM module, and that is forced by
//! an existing security control rather than chosen. Plaid takes its
//! `access_token` in the JSON request BODY; a Talos module cannot put a secret
//! there (`vault://` resolves into headers only, `get_secret` yields an opaque
//! handle, and `expose_secret` is hardcoded off on every dispatch path). So it
//! joins `talos-gmail`, `talos-google-calendar` and `talos-google-cloud`.
//!
//! # Data posture
//!
//! Financial transactions are the most sensitive data this platform touches.
//! The rules that follow from that, and which the rest of this crate is built
//! to keep:
//!
//! * **Nothing is logged that identifies an account or a person.** No access
//!   token, no public token, no account number or mask, no merchant string.
//!   Logs carry Plaid's own error codes, item ids, and counts.
//! * **Every credential-bearing type has a hand-written redacting `Debug`**
//!   (lint 37), so a token cannot reach a panic message or an `anyhow` chain.
//! * **Every response body is read capped** (lint 31) and **every paginated
//!   loop is bounded** — and when a bound binds, the caller is TOLD
//!   (`SyncPage::truncated`) rather than handed a prefix that looks whole.
//! * **An unknown environment refuses.** There is no safe default host for a
//!   real credential.
//!
//! The actor that consumes this must be `max_llm_tier = tier1` with
//! `egress_scope = public`: tier-1 structurally bars every external LLM
//! provider, so transaction data cannot reach one, while the public egress
//! scope still permits the HTTPS call to Plaid itself. That is stricter than
//! the tier-2 posture the work actor uses, and deliberately so.

pub mod client;
pub mod config;

pub use client::{
    AccessToken, Account, Balances, PfCategory, PlaidApiError, PlaidClient, PublicToken, SyncPage,
    Transaction,
};
pub use config::{ConfigError, PlaidConfig, PlaidEnv};
