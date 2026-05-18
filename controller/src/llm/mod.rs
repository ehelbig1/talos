//! Re-export shim for the extracted `talos-llm` crate.
//!
//! Both LLM clients live in `talos-llm`: `LlmClient` (Anthropic, vault-
//! first via `SecretsManager::get_llm_vault_keys`) and `OllamaClient`
//! (local Tier-1). The crate has no controller-internal dependencies —
//! the only `crate::*` import in the original was `crate::secrets::
//! SecretsManager`, which is itself a re-export shim of
//! `talos_secrets_manager::SecretsManager`. The shim keeps
//! `crate::llm::LlmClient` / `crate::llm::OllamaClient` resolving for
//! the three call-sites in `main.rs`, `mcp/mod.rs`, and
//! `api/schema/workflows/mutations.rs`.

#![allow(unused_imports)]

pub use talos_llm::*;
