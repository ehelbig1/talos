//! Size-aware routing for compiled module bytes in NATS dispatches.
//!
//! Rust components are ~100KB and ride INLINE in the `DispatchJob` (no
//! Redis dependency, HMAC covers the bytes). Interpreter-toolchain
//! components (componentize-py ~18MB, jco ~13MB — embedded runtimes)
//! exceed NATS's `max_payload` (8 MiB in the reference deploys), so
//! oversized modules dispatch by their `redis:wasm:{id}` URI instead:
//! the registry pre-warms that key on module load, the worker's fetch is
//! size-capped (`WORKER_MAX_OCI_LAYER_BYTES`, default 32 MiB), and the
//! dispatch carries `expected_wasm_hash` so the worker's integrity check
//! refuses substituted bytes (an attacker with Redis write access cannot
//! swap the module — the hash is HMAC-bound in the `JobRequest`).

/// Ceiling for inline-embedded module bytes. Env-tunable via
/// `TALOS_INLINE_WASM_MAX_BYTES`; the 4 MiB default leaves generous
/// headroom under the 8 MiB NATS `max_payload` for the input payload,
/// secrets envelope, and JSON framing that share the message.
pub(crate) fn inline_wasm_cap_bytes() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("TALOS_INLINE_WASM_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(4 * 1024 * 1024)
    })
}

/// Whether these module bytes ride inline (non-empty AND under the cap).
/// Empty bytes always route by URI (OCI modules); oversized bytes route
/// by `redis:wasm:` URI + `expected_wasm_hash`.
pub(crate) fn embeds_inline(wasm_bytes: &[u8]) -> bool {
    !wasm_bytes.is_empty() && wasm_bytes.len() <= inline_wasm_cap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_oversized_route_by_uri_small_rides_inline() {
        assert!(!embeds_inline(&[]));
        assert!(embeds_inline(&[0u8; 1024]));
        let oversized = vec![0u8; inline_wasm_cap_bytes() + 1];
        assert!(!embeds_inline(&oversized));
    }
}
