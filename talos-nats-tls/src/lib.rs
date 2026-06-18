//! Shared NATS in-cluster TLS wiring for the controller + worker connect
//! paths, so the CA-trust logic is a single source of truth and can't drift
//! between the two binaries.
//!
//! The chart's in-cluster NATS terminates TLS with a self-signed cert (see
//! `deploy/helm/talos/templates/tls/incluster-certs.yaml`). Both the
//! controller and the worker connect with a `tls://` URL and must trust that
//! cert. This helper adds the mounted CA/cert as a trusted root and requires
//! TLS when [`NATS_CA_FILE_ENV`] is set — closing the loop on the production
//! transmission-security gate (PR #243), which rejects a plaintext NATS_URL.

use async_nats::ConnectOptions;

/// Env var naming the PEM file the NATS client trusts as a root certificate.
/// In-cluster this is the NATS server's own self-signed cert (a self-signed
/// cert is its own trust anchor); the chart mounts it into the controller and
/// worker pods. Unset for an external NATS fronted by a publicly-trusted CA, or
/// for plaintext dev.
pub const NATS_CA_FILE_ENV: &str = "NATS_CA_FILE";

/// If [`NATS_CA_FILE_ENV`] names a non-empty PEM path, add it as a trusted root
/// and require TLS — this is how the controller + worker trust the chart's
/// self-signed in-cluster NATS cert over a `tls://` URL.
///
/// No-op when the env var is unset/empty, so existing deployments (external
/// NATS with a public-CA cert, or plaintext dev) are unaffected. The `tls://`
/// scheme in `NATS_URL` already negotiates TLS; this adds the trust anchor the
/// self-signed cert needs and pins `require_tls` so a downgrade can't slip
/// through.
#[must_use]
pub fn apply_nats_ca(opts: ConnectOptions) -> ConnectOptions {
    match std::env::var(NATS_CA_FILE_ENV) {
        Ok(path) if !path.trim().is_empty() => {
            tracing::info!(
                target: "talos_nats",
                ca_file = %path,
                "NATS client: trusting CA root + requiring TLS"
            );
            opts.add_root_certificates(path.into()).require_tls(true)
        }
        _ => opts,
    }
}
