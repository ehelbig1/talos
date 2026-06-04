//! Re-export shim. The controller-side SSRF resolver + the SSRF-safe
//! outbound-webhook client builder were hoisted into `talos-http-utils`
//! (next to the call-time `ssrf` check) so the sibling fire sites in
//! `talos-engine` / `talos-execution-orchestration` — which sit BELOW this
//! crate in the dependency graph and so could not reach the resolver here —
//! can build the same SSRF-safe client. See
//! `talos_http_utils::outbound` for the implementation and rationale.
//!
//! Existing `talos-mcp-handlers` call sites continue to resolve through this
//! shim.
pub use talos_http_utils::outbound::{
    build_outbound_webhook_client, build_outbound_webhook_client_with_timeout,
    ControllerSsrfResolver,
};
