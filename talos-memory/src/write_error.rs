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

    /// The actor already holds `limit` (= `MAX_MEMORIES_PER_ACTOR`)
    /// `actor_memory` rows and this write would add a NEW key. Raised by the
    /// capped persist statement after it has also reclaimed the actor's
    /// already-expired rows once (2026-09-25). An overwrite of an existing
    /// key is never refused.
    ///
    /// Its own label (`"quota"`) rather than `"validation"`: the write is
    /// well-formed and would succeed for a different actor, so a sustained
    /// bump means "an actor is at its ceiling" — typically a module writing a
    /// fresh key per run without ever deleting — not "a module emits bad
    /// envelopes". Low blast radius (one actor, new keys only). The message
    /// names the remedy and carries no caller data.
    #[error(
        "actor_memory quota exceeded: this actor already holds the maximum of {limit} \
         memories; overwrite an existing key, or delete unused memories, before adding \
         new keys"
    )]
    QuotaExceeded { limit: i64 },
}

impl MemoryWriteError {
    /// Stable Prometheus label for this failure class. The five values
    /// (`"crypto"`, `"db"`, `"validation"`, `"other"`, `"quota"`) are the
    /// label values `talos_metrics::memory_write_failures_total` is scraped
    /// with in dashboards/alerts — do not rename an existing value
    /// without a coordinated dashboard update; adding a new variant
    /// (with a new label) is safe, but it must also be added to that
    /// counter's pre-seed loop in `talos-metrics` (absent is not zero).
    #[must_use]
    pub fn metric_label(&self) -> &'static str {
        match self {
            MemoryWriteError::Crypto(_) => "crypto",
            MemoryWriteError::Db(_) => "db",
            MemoryWriteError::Validation(_) => "validation",
            MemoryWriteError::Other(_) => "other",
            MemoryWriteError::QuotaExceeded { .. } => "quota",
        }
    }

    /// Every label [`Self::metric_label`] can return, in declaration order.
    /// `talos-metrics` pre-seeds these at 0; it cannot depend on this crate,
    /// so its list is a copy, pinned by
    /// `every_metric_label_is_pre_seeded_at_zero` in this module's tests.
    pub const METRIC_LABELS: &'static [&'static str] =
        &["crypto", "db", "validation", "other", "quota"];
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
        assert_eq!(
            MemoryWriteError::QuotaExceeded { limit: 10_000 }.metric_label(),
            "quota"
        );
    }

    /// `METRIC_LABELS` must be exactly the set `metric_label` can return —
    /// it is what the metrics pre-seed is pinned to, so a variant added
    /// without extending it would leave its series absent until the first
    /// failure (absent is not zero). Built from one instance per variant;
    /// the exhaustive `match` below fails to compile when a variant is added,
    /// which is what forces this list to be revisited.
    #[test]
    fn metric_labels_list_every_variant_exactly_once() {
        let every_variant = [
            MemoryWriteError::Crypto(anyhow::anyhow!("x")),
            MemoryWriteError::Db(anyhow::anyhow!("x")),
            MemoryWriteError::Validation(anyhow::anyhow!("x")),
            MemoryWriteError::Other(anyhow::anyhow!("x")),
            MemoryWriteError::QuotaExceeded { limit: 1 },
        ];
        for v in &every_variant {
            // Exhaustiveness tripwire — no wildcard arm on purpose.
            match v {
                MemoryWriteError::Crypto(_)
                | MemoryWriteError::Db(_)
                | MemoryWriteError::Validation(_)
                | MemoryWriteError::Other(_)
                | MemoryWriteError::QuotaExceeded { .. } => {}
            }
        }
        let labels: Vec<&str> = every_variant
            .iter()
            .map(MemoryWriteError::metric_label)
            .collect();
        assert_eq!(labels, MemoryWriteError::METRIC_LABELS);
    }

    /// Every label this enum can emit must render at 0 on a COLD registry:
    /// an unseeded label is ABSENT until its first failure, and
    /// `increase(...)` over an absent series matches nothing, so a first
    /// quota refusal would be invisible to a rate query. `talos-metrics`
    /// keeps its own copy of the list (it cannot import this crate); this is
    /// where the two meet.
    #[test]
    fn every_metric_label_is_pre_seeded_at_zero() {
        let m = talos_metrics::TalosMetrics::new().expect("cold registry");
        let rendered = m.render_prometheus().expect("render");
        for label in MemoryWriteError::METRIC_LABELS {
            let line = format!(r#"talos_memory_write_failures_total{{reason="{label}"}} 0"#);
            assert!(
                rendered.contains(&line),
                "`{label}` is emitted by MemoryWriteError::metric_label but not \
                 pre-seeded in talos-metrics; expected the line {line}"
            );
        }
    }

    /// The quota refusal survives the anyhow wrapper the `persist_memory*`
    /// wrappers return, so callers can render it by `downcast_ref`.
    #[test]
    fn quota_refusal_is_recoverable_through_anyhow() {
        let err: anyhow::Error = MemoryWriteError::QuotaExceeded { limit: 10_000 }.into();
        let err = err.context("outer context a caller added");
        assert!(matches!(
            err.downcast_ref::<MemoryWriteError>(),
            Some(MemoryWriteError::QuotaExceeded { limit: 10_000 })
        ));
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
