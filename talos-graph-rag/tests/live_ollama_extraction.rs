//! Live end-to-end proof of provider-agnostic (local-Ollama) triple
//! extraction. `#[ignore]` by default — it needs a running Neo4j AND a
//! reachable Ollama with the extraction model pulled, so it never runs
//! in CI. Run explicitly against the dev stack:
//!
//! ```bash
//! NEO4J_URI=bolt://127.0.0.1:7687 NEO4J_USER=neo4j \
//! NEO4J_PASSWORD=<pw> GRAPH_RAG_TEST_OLLAMA_URL=http://127.0.0.1:11434 \
//! GRAPH_RAG_TEST_MODEL=qwen2.5-coder:7b \
//!   cargo test -p talos-graph-rag --test live_ollama_extraction -- --ignored --nocapture
//! ```
//!
//! Exercises the REAL code path: `extract_and_store_entities` →
//! `extract_triples_llm` dispatcher → `extract_triples_ollama` (JSON-mode
//! against the live model) → `parse_triples_from_values` → batched Neo4j
//! upsert. `actor_repo` is left unwired so the legacy-ungated tier path
//! runs (this test asserts the OLLAMA BACKEND works; the tier gate is
//! covered by `tier_gate_tests` in the crate).

use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires live Neo4j + Ollama"]
async fn ollama_backend_populates_graph_end_to_end() {
    let ollama_url = std::env::var("GRAPH_RAG_TEST_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let model =
        std::env::var("GRAPH_RAG_TEST_MODEL").unwrap_or_else(|_| "qwen2.5-coder:7b".to_string());

    let service = talos_graph_rag::GraphRagService::new()
        .await
        .expect("neo4j connect failed — is the dev stack up + NEO4J_* set?")
        .expect("NEO4J_URI not set");

    let ollama = Arc::new(talos_llm::OllamaClient::new(ollama_url.clone()));
    let service = service.with_ollama(ollama, model.clone());

    // Report the deployment-level backend signal — proves the graph_stats
    // envelope field resolves to the local backend when no Anthropic key
    // is present.
    let backend = service.extraction_backend().await;
    println!("extraction_backend = {backend}");
    assert!(
        backend == "ollama" || backend == "anthropic+ollama",
        "expected ollama to be a configured backend, got {backend}"
    );

    // Fresh actor id → clean, isolated node/edge counts.
    let actor_id = Uuid::new_v4();
    let memory_key = "meeting_notes"; // NOT a rule-based key → forces the LLM path.
    let value = serde_json::json!({
        "notes": "Alice works on the Talos project. Bob is assigned to ticket TAL-42, \
                  which is blocked by ticket TAL-40. The Q3 planning meeting discussed \
                  the Talos project and was attended by Alice and Bob."
    });

    let count = service
        .extract_and_store_entities(actor_id, memory_key, &value)
        .await
        .expect("extraction returned an error");

    println!("extracted + stored {count} triples for actor {actor_id}");
    assert!(
        count > 0,
        "Ollama extraction produced no triples — graph would stay empty"
    );

    // Confirm the triples actually landed in Neo4j (real upsert, not just
    // an in-memory count).
    let stats = service.get_stats(actor_id).await.expect("get_stats failed");
    println!(
        "graph stats: {}",
        serde_json::to_string_pretty(&stats).unwrap()
    );

    let total_nodes: i64 = stats
        .get("nodes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter().fold(0, |acc, n| {
                acc + n.get("count").and_then(|c| c.as_i64()).unwrap_or(0)
            })
        })
        .unwrap_or(0);
    assert!(total_nodes > 0, "no nodes persisted to Neo4j");
}

#[tokio::test]
#[ignore = "requires live Neo4j + Ollama + Postgres actor repo"]
async fn tier1_actor_skips_ollama_backend() {
    // Wire a real ActorRepository so the tier gate is active. A tier1
    // actor must produce ZERO triples even with Ollama configured —
    // the data-egress guarantee is not weakened by the local backend.
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&db_url)
        .await
        .expect("pg connect");
    let actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(pool.clone()));

    let tier1_actor: Uuid = std::env::var("GRAPH_RAG_TEST_TIER1_ACTOR")
        .expect("set GRAPH_RAG_TEST_TIER1_ACTOR to a tier1 actor id")
        .parse()
        .expect("valid uuid");

    let ollama = Arc::new(talos_llm::OllamaClient::new(
        std::env::var("GRAPH_RAG_TEST_OLLAMA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
    ));
    let service = talos_graph_rag::GraphRagService::new()
        .await
        .unwrap()
        .unwrap()
        .with_actor_repo(actor_repo)
        .with_ollama(
            ollama,
            std::env::var("GRAPH_RAG_TEST_MODEL")
                .unwrap_or_else(|_| "qwen2.5-coder:7b".to_string()),
        );

    let value = serde_json::json!({"notes": "Carol works on the Phoenix project."});
    let count = service
        .extract_and_store_entities(tier1_actor, "meeting_notes", &value)
        .await
        .expect("no error");
    println!("tier1 actor produced {count} triples (must be 0)");
    assert_eq!(count, 0, "tier1 actor leaked data to a local LLM backend");
}
