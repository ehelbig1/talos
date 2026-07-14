//! Typed error boundary for the `actor_memory` write path.
//!
//! `persist_memory_with_metadata` (lib.rs) has one anyhow-context-wrapped
//! call chain per stage (validation, encryption, DB), and prior to this
//! type existing, callers that needed to classify a write failure for
//! metric labelling (`talos-engine::node_hook`) did so by substring-
//! matching `err.to_string()`. Any `anyhow::Context::context(...)` call
//! anywhere in the chain — including ones added later, in code the
//! classifier's author never saw — silently changes the string and can
//! demote a crypto/db failure into the `"other"` bucket, muting alerts
//! (finding N-5, crate review 2026-05-05).
//!
//! [`MemoryWriteError`] fixes this by classifying AT THE SOURCE, where
//! the concrete failing operation is still known, and exposing
//! [`MemoryWriteError::metric_label`] as the single place that maps a
//! variant to its Prometheus label. `Display`/`Debug` (and therefore
//! `.to_string()` / `{:#}` context chains) can still change freely —
//! they no longer feed classification.
//!
//! Scope: this type is intentionally narrow. It is NOT a workspace-wide
//! conversion of `talos-memory`'s public API to typed errors — most
//! callers (MCP handlers, GraphQL mutations, the RPC subscriber, actor
//! scaffolding) have no need to distinguish failure classes and keep
//! using the existing `anyhow::Result`-returning `persist_memory` /
//! `persist_memory_with_metadata`. Only the typed sibling
//! `persist_memory_with_metadata_typed` (used by `node_hook`, the sole
//! caller that classifies for metrics) returns this type; the anyhow
//! version delegates to it and converts the error back via `Into`.
use thiserror::Error;

/// Failure classification for an `actor_memory` write, carrying the
/// underlying error as context for logs while keeping the variant
/// itself independent of the error's rendered text.
#[derive(Error, Debug)]
pub enum MemoryWriteError {
    /// Failed inside the encrypt/DEK pipeline — `MemoryCryptoHook::encrypt`
    /// itself, DEK resolution/wrapping underneath it, or the missing-hook
    /// fail-closed guard in production. High blast radius: every write
    /// for the affected org/actor is failing, not just this key.
    #[error("actor_memory crypto operation failed: {0}")]
    Crypto(#[source] anyhow::Error),

    /// Failed on a Postgres round-trip — the `actors.org_id` lookup or
    /// the `INSERT ... ON CONFLICT` itself. High blast radius: usually
    /// means the DB is unreachable or the pool is exhausted, not that
    /// this particular write is malformed.
    #[error("actor_memory database operation failed: {0}")]
    Db(#[source] anyhow::Error),

    /// The caller-supplied key / value / metadata / memory_type failed
    /// input validation (bad key shape, oversized value/metadata, unknown
    /// memory_type). Low blast radius: this specific write is malformed,
    /// other writes from the same actor are unaffected. Distinct from
    /// `Other` — introduced as its own metric label rather than folded
    /// into `"other"` because it is strictly more informative for
    /// operators triaging alerts (a spike in `validation` means "a
    /// module is emitting bad envelopes", not "the DB/crypto path is
    /// down"). Pre-typed-error behavior routed these to `"other"`
    /// (neither `MEMORY_WRITE_CRYPTO_MARKERS` nor `MEMORY_WRITE_DB_MARKERS`
    /// matched validation error text).
    #[error("actor_memory write validation failed: {0}")]
    Validation(#[source] anyhow::Error),

    /// Anything that isn't one of the above. Kept as an explicit
    /// catch-all (rather than folding into `Validation`) so a genuinely
    /// unclassified failure stays visible under `"other"` instead of
    /// polluting the validation bucket.
    #[error("actor_memory write failed: {0}")]
    Other(#[source] anyhow::Error),
}

impl MemoryWriteError {
    /// Stable Prometheus label for this failure class. The four values
    /// (`"crypto"`, `"db"`, `"validation"`, `"other"`) are the label
    /// values `talos_metrics::memory_write_failures_total` is scraped
    /// with in dashboards/alerts — do not rename an existing value
    /// without a coordinated dashboard update; adding a new variant
    /// (with a new label) is safe.
    #[must_use]
    pub fn metric_label(&self) -> &'static str {
        match self {
            MemoryWriteError::Crypto(_) => "crypto",
            MemoryWriteError::Db(_) => "db",
            MemoryWriteError::Validation(_) => "validation",
            MemoryWriteError::Other(_) => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryWriteError;

    /// The whole point of the typed boundary: wrapping the source error
    /// in additional `anyhow::Context` (as any intermediate call site is
    /// free to do, today or in a future refactor) must NOT change the
    /// emitted metric label. Pre-fix, `classify_memory_write_failure`
    /// substring-matched `err.to_string()`, so a `.context("wrapped")`
    /// anywhere upstream could shift the rendered string enough to fall
    /// through both marker lists into `"other"`, silently muting a
    /// crypto or db alert.
    #[test]
    fn context_wrapping_does_not_change_classification() {
        let base = anyhow::anyhow!("aead::Error: tag mismatch during decrypt_dek");
        let wrapped = base
            .context("persisting actor_memory row")
            .context("__memory_write__ protocol handler")
            .context("on_node_completed hook");
        assert_eq!(
            MemoryWriteError::Crypto(wrapped).metric_label(),
            "crypto",
            "context-wrapping must not demote a crypto failure to another bucket"
        );

        let base = anyhow::anyhow!("connection reset by peer");
        let wrapped = base.context("Failed to persist actor memory");
        assert_eq!(MemoryWriteError::Db(wrapped).metric_label(), "db");

        let base = anyhow::anyhow!("value too large (70000 bytes)");
        let wrapped = base.context("validating __memory_write__ envelope");
        assert_eq!(
            MemoryWriteError::Validation(wrapped).metric_label(),
            "validation"
        );

        let base = anyhow::anyhow!("something unexpected");
        let wrapped = base.context("deep in an unrelated call chain");
        assert_eq!(MemoryWriteError::Other(wrapped).metric_label(), "other");
    }

    #[test]
    fn each_variant_maps_to_its_label() {
        assert_eq!(
            MemoryWriteError::Crypto(anyhow::anyhow!("x")).metric_label(),
            "crypto"
        );
        assert_eq!(
            MemoryWriteError::Db(anyhow::anyhow!("x")).metric_label(),
            "db"
        );
        assert_eq!(
            MemoryWriteError::Validation(anyhow::anyhow!("x")).metric_label(),
            "validation"
        );
        assert_eq!(
            MemoryWriteError::Other(anyhow::anyhow!("x")).metric_label(),
            "other"
        );
    }

    /// A `MemoryWriteError` must convert into `anyhow::Error` via `?` /
    /// `.into()` so `persist_memory_with_metadata` (the pre-existing
    /// anyhow-returning API every other caller keeps using) can delegate
    /// to the typed sibling without callers seeing a signature change.
    #[test]
    fn converts_into_anyhow_error() {
        let err = MemoryWriteError::Db(anyhow::anyhow!("pool exhausted"));
        let anyhow_err: anyhow::Error = err.into();
        assert!(anyhow_err.to_string().contains("database operation failed"));
    }
}
