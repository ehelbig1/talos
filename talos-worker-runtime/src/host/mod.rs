//! Host function implementations for all WIT interfaces.
//!
//! Each `impl <interface>::Host for TalosContext` block provides the host side
//! of one WIT interface imported by the `automation-node` world.
//!
//! Split out of the former single-file `host_impl.rs` into per-interface
//! modules (May-2026 workspace hygiene). Every submodule is glob
//! re-exported here so `crate::host::<item>` — and, via the
//! `crate::host_impl` re-export shim — `crate::host_impl::<item>` keep
//! resolving exactly as before the split. Shared plumbing (the `wit_*`
//! binding aliases, `TalosContext`, cross-interface constants and
//! helpers) flows into each submodule through its `use super::*;`.

pub(crate) use crate::circuit_breaker::get_global_circuit_breaker;
pub(crate) use crate::context::TalosContext;

// Bring the generated WIT bindings into scope.
pub(crate) use crate::bindings::talos::core::{
    agent_memory as wit_agent_memory, agent_orchestration as wit_agent_orchestration,
    cache as wit_cache, context_window as wit_context_window, crypto as wit_crypto,
    data_transform as wit_data_transform, database as wit_database, datetime as wit_datetime,
    email as wit_email, embedding as wit_embedding, env as wit_env, events as wit_events,
    files as wit_files, graph_memory as wit_graph_memory, graphql as wit_graphql, http as wit_http,
    http_stream as wit_http_stream, integration_state as wit_integration_state, json as wit_json,
    llm as wit_llm, llm_streaming as wit_llm_streaming, llm_tools as wit_llm_tools,
    logging as wit_logging, messaging as wit_messaging, model as wit_model,
    object_storage as wit_object_storage, resource_quotas as wit_resource_quotas,
    secrets as wit_secrets, state as wit_state, templates as wit_templates, webhook as wit_webhook,
};
pub(crate) use futures_util::StreamExt;
pub(crate) use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "../host_impl_tests.rs"]
mod host_impl_tests;

mod cache;
mod crypto;
mod data;
mod database;
mod egress;
mod email;
mod files;
mod governance;
mod graphql;
mod http;
mod http_stream;
mod integration_state;
mod limits;
mod llm;
pub(crate) mod llm_providers;
mod llm_streaming;
mod llm_tools;
mod logging;
mod memory;
mod messaging;
mod model;
mod object_storage;
mod orchestration;
mod secrets;
mod state;
mod vault;
mod webhook;

// Glob re-exports keep every item reachable at `crate::host::<item>`
// (and, via the `host_impl` shim, `crate::host_impl::<item>`) exactly
// as before the split. Some submodules currently export nothing that
// other modules reference — the narrow allow keeps the re-export
// surface uniform instead of curating per-module (same pattern as the
// `trace_nats` / `audit` re-export shims).
#[allow(unused_imports)]
pub(crate) use cache::*;
#[allow(unused_imports)]
pub(crate) use crypto::*;
#[allow(unused_imports)]
pub(crate) use data::*;
#[allow(unused_imports)]
pub(crate) use database::*;
#[allow(unused_imports)]
pub(crate) use egress::*;
#[allow(unused_imports)]
pub(crate) use email::*;
#[allow(unused_imports)]
pub(crate) use files::*;
#[allow(unused_imports)]
pub(crate) use governance::*;
#[allow(unused_imports)]
pub(crate) use graphql::*;
#[allow(unused_imports)]
pub(crate) use http::*;
#[allow(unused_imports)]
pub(crate) use http_stream::*;
#[allow(unused_imports)]
pub(crate) use integration_state::*;
#[allow(unused_imports)]
pub(crate) use limits::*;
#[allow(unused_imports)]
pub(crate) use llm::*;
#[allow(unused_imports)]
pub(crate) use llm_streaming::*;
#[allow(unused_imports)]
pub(crate) use llm_tools::*;
#[allow(unused_imports)]
pub(crate) use logging::*;
#[allow(unused_imports)]
pub(crate) use memory::*;
#[allow(unused_imports)]
pub(crate) use messaging::*;
#[allow(unused_imports)]
pub(crate) use object_storage::*;
#[allow(unused_imports)]
pub(crate) use orchestration::*;
#[allow(unused_imports)]
pub(crate) use secrets::*;
#[allow(unused_imports)]
pub(crate) use state::*;
#[allow(unused_imports)]
pub(crate) use vault::*;
#[allow(unused_imports)]
pub(crate) use webhook::*;

// `verify_signed_agent_envelope` was `pub` (crate-external) in the
// pre-split host_impl.rs — keep it exported at the same visibility.
pub use orchestration::verify_signed_agent_envelope;
