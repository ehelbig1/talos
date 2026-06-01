//! Worker self-reported identity.
//!
//! Extracted from `main.rs` (was `pub(crate) fn worker_identity`) so the
//! library — specifically `host_impl::build_signed_agent_envelope` — can
//! reference the same resolved identity that `main.rs::handle_*` paths
//! pass to `JobResult::sign_with_worker_id`. Pre-extraction the function
//! lived in the binary only; `host_impl.rs` (library code) could not see
//! it, so a duplicate `OnceLock` inside the library would have cached a
//! distinct value, breaking forensic attribution at signed-envelope
//! subscribers.
//!
//! L-11 (2026-05-22): The worker's self-reported identity, bound into
//! every signed [`talos_workflow_job_protocol::JobResult`] /
//! [`talos_workflow_job_protocol::PipelineJobResult`] via
//! `sign_with_worker_id`.
//!
//! Resolution order:
//!   1. `TALOS_WORKER_ID` env var (operator-supplied, explicit).
//!   2. `HOSTNAME` env var (Kubernetes injects this automatically as
//!      the pod name — typically `talos-worker-<rs>-<5hex>`).
//!   3. A random 16-byte hex string generated once at startup
//!      (`fallback-<hex>`). This branch only fires in dev containers
//!      that have neither env set.
//!
//! The result is sanitized to the
//! [`talos_workflow_job_protocol::validate_worker_id`] charset
//! (`[A-Za-z0-9._-]{0,128}`) and cached in a [`std::sync::OnceLock`] so
//! every signing call site reads the same value without re-parsing env
//! each time.
//!
//! Note: this is NOT cryptographic identity — any process holding
//! `WORKER_SHARED_KEY` can sign as any `worker_id`. It is forensic
//! visibility (which pod produced which result, surfaced in the
//! controller's audit log) plus the wire-format anchor that a future
//! per-worker HKDF subkey scheme can dispatch on.

use std::sync::OnceLock;

static WORKER_ID: OnceLock<String> = OnceLock::new();

/// Returns the worker's resolved identity. Idempotent; cached on first call.
pub fn worker_identity() -> &'static str {
    WORKER_ID.get_or_init(resolve_worker_id)
}

fn resolve_worker_id() -> String {
    // 1. TALOS_WORKER_ID — explicit operator override.
    if let Ok(v) = std::env::var("TALOS_WORKER_ID") {
        let v = v.trim();
        if !v.is_empty() {
            let sanitized = sanitize(v);
            if !sanitized.is_empty() {
                return sanitized;
            }
        }
    }

    // 2. HOSTNAME — Kubernetes pod name in cluster deployments.
    if let Ok(v) = std::env::var("HOSTNAME") {
        let v = v.trim();
        if !v.is_empty() {
            let sanitized = sanitize(v);
            if !sanitized.is_empty() {
                return sanitized;
            }
        }
    }

    // 3. Random fallback — dev / CI containers without HOSTNAME.
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let id = format!("fallback-{}", hex::encode(buf));
    tracing::warn!(
        worker_id = %id,
        "TALOS_WORKER_ID and HOSTNAME both unset — using random fallback. \
         Set TALOS_WORKER_ID (or rely on Kubernetes pod-name HOSTNAME) for \
         stable forensic attribution across restarts."
    );
    id
}

/// Sanitize a raw identity string to the
/// [`talos_workflow_job_protocol::validate_worker_id`] charset. Out-of-set
/// characters become `-`; the result is truncated to `MAX_WORKER_ID_LEN`.
fn sanitize(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if s.len() > talos_workflow_job_protocol::MAX_WORKER_ID_LEN {
        s.truncate(talos_workflow_job_protocol::MAX_WORKER_ID_LEN);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::worker_identity;

    #[test]
    fn returns_validatable_id() {
        let id = worker_identity();
        talos_workflow_job_protocol::validate_worker_id(id)
            .expect("resolved worker_id must satisfy validate_worker_id");
    }

    #[test]
    fn cached_across_calls() {
        let a: &'static str = worker_identity();
        let b: &'static str = worker_identity();
        assert_eq!(
            a.as_ptr(),
            b.as_ptr(),
            "OnceLock should cache the same allocation"
        );
    }
}
