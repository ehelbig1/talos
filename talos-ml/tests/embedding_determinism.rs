//! The load-bearing assumption behind embedding-keyed content identity.
//!
//! `DatasetService::dedupe_by_content` treats `md5(embedding::text)` as the
//! content key for an example — i.e. it assumes the configured embedding
//! provider returns a BIT-IDENTICAL vector for identical text, indefinitely.
//! Nothing else in the tree asserts that. The in-process embedding LRU hides
//! the question for ~300 s / 128 entries, but duplicates that matter arrive
//! days apart (the CI alert that fires again next week), long past the cache.
//! If the provider ever became non-deterministic (non-pinned model version,
//! GPU non-determinism, load-balanced heterogeneous backends), dedupe would
//! silently stop collapsing anything and the duplicate-vote defect that
//! motivated it would return unnoticed.
//!
//! Gated on a configured provider, in the style of the `make test-integration`
//! suite: without one, each test prints a skip note and passes. It is NOT
//! registered in `scripts/test-integration.sh` because that harness provisions
//! Postgres / Redis / NATS but no embedder.
//!
//! ## Running
//!
//! ```sh
//! export EMBEDDING_API_URL="http://localhost:11434/v1/embeddings"
//! export EMBEDDING_MODEL="mxbai-embed-large"
//! export EMBEDDING_DIMENSIONS=1024
//! cargo test -p talos-ml --test embedding_determinism -- --nocapture
//! ```

use talos_memory::embedding;

fn provider_configured() -> bool {
    embedding::EmbeddingConfig::cached().is_some()
}

/// Same text twice, with the process cache cleared in between so the second
/// call genuinely re-hits the provider: the vectors must be bit-identical.
#[tokio::test]
async fn identical_text_embeds_to_a_bit_identical_vector() {
    if !provider_configured() {
        eprintln!(
            "skipping: no embedding provider configured \
             (set EMBEDDING_API_URL / EMBEDDING_API_KEY)"
        );
        return;
    }
    let text = "Subject: [CI] Run failed: build #4211\nFrom: notifications@github.com";

    embedding::clear_cache();
    let Some(first) = embedding::generate_embedding(text, true).await else {
        eprintln!("skipping: provider configured but returned no vector (unreachable/local-only)");
        return;
    };
    // Clearing is what makes this a PROVIDER test rather than a cache test.
    embedding::clear_cache();
    let second = embedding::generate_embedding(text, true)
        .await
        .expect("second embedding must succeed once the first did");

    assert_eq!(
        first.len(),
        second.len(),
        "dimensionality must be stable across calls"
    );
    assert_eq!(
        first, second,
        "embedding must be BIT-identical for identical text — \
         ml_examples content dedupe keys on md5(embedding::text), so any drift \
         silently stops collapsing duplicates"
    );

    // Different text must not collide (the other half of "usable as a key").
    embedding::clear_cache();
    let other = embedding::generate_embedding("Subject: lunch tomorrow?", true)
        .await
        .expect("third embedding");
    assert_ne!(first, other, "different text must not share a content key");
}
