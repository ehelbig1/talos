//! # Graph RAG Service
//!
//! Knowledge graph layer backed by Neo4j. Stores entity-relationship
//! triples extracted from actor memory writes (people, tickets, projects,
//! emails, meetings) and provides hybrid retrieval that combines graph
//! traversal with pgvector similarity for richer context injection.
//!
//! ## Architecture
//!
//! - **Entity extraction**: When `persist_memory` stores a memory, it
//!   also calls `extract_and_store_entities` which uses the LLM to
//!   identify entities and relationships in the memory value, then
//!   writes them to Neo4j as labeled nodes + typed edges.
//! - **Hybrid retrieval**: `get_graph_context` takes a query string,
//!   finds matching entities via full-text search, traverses 1-2 hops
//!   to find related entities, and returns the subgraph as structured
//!   context for the LLM.
//! - **Actor isolation**: Every node carries an `actor_id` property.
//!   All queries filter by actor_id to prevent cross-actor leakage.
//!
//! ## Graph Schema
//!
//! Node labels: Person, Ticket, Project, Email, Meeting, Concept
//! Edge types: WORKS_ON, ASSIGNED_TO, DISCUSSED_IN, ATTENDED, RELATED_TO,
//!             MENTIONED_IN, BLOCKED_BY, CREATED
//!
//! All nodes have: `name` (display), `actor_id` (isolation), `source_key`
//! (which actor_memory key this was extracted from), `updated_at`.

use anyhow::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

/// Graph RAG service backed by Neo4j.
pub struct GraphRagService {
    graph: Arc<neo4rs::Graph>,
    /// Vault-backed Anthropic key resolver for the LLM-fallback
    /// extraction path. When `None`, we fall back to
    /// `ANTHROPIC_API_KEY` env (the original behaviour). When
    /// `Some`, the controller has wired in a `SecretsManager` and
    /// we prefer the vault entry — so `rotate_secret anthropic/api_key`
    /// propagates to the next extraction call without a process
    /// restart.
    secrets: Option<Arc<talos_secrets_manager::SecretsManager>>,
    /// Actor repository for `max_llm_tier` ceiling lookups. When
    /// wired in (`with_actor_repo`), the LLM-fallback extraction
    /// path is gated: tier1 ("local-only / Ollama") actors must not
    /// have memory contents sent to Anthropic for triple extraction.
    /// When `None`, the legacy "trust the deployment" behaviour
    /// applies — operators who don't want any data egress should
    /// either wire this in or unset `ANTHROPIC_API_KEY` env (the
    /// extraction path falls off both gates).
    actor_repo: Option<Arc<talos_actor_repository::ActorRepository>>,
}

impl GraphRagService {
    /// Attach a `SecretsManager` for vault-first Anthropic key
    /// resolution in `extract_triples_via_llm`. Builder method so
    /// `controller/src/main.rs` can keep its existing
    /// `GraphRagService::new().await?.with_secrets(sm)` shape.
    /// When unset, the LLM-fallback path uses `ANTHROPIC_API_KEY`
    /// from the process env (legacy behaviour).
    #[must_use]
    pub fn with_secrets(mut self, secrets: Arc<talos_secrets_manager::SecretsManager>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Attach an `ActorRepository` so the LLM-fallback extraction
    /// path can gate on the actor's `max_llm_tier` ceiling. Tier1
    /// actors are policy-bound to keep data on-host (local Ollama
    /// only) — extraction skips the Anthropic call for those, even
    /// when a vault key is present. Without this builder, the
    /// extraction path runs unchecked (legacy behaviour).
    ///
    /// Fail-closed: if the tier lookup errors at extraction time,
    /// LLM extraction is skipped — same fail-closed contract as
    /// `talos_engine::actor_binding::apply_actor_to_engine`.
    #[must_use]
    pub fn with_actor_repo(
        mut self,
        actor_repo: Arc<talos_actor_repository::ActorRepository>,
    ) -> Self {
        self.actor_repo = Some(actor_repo);
        self
    }

    /// Connect to Neo4j and initialize schema constraints.
    pub async fn new() -> Result<Option<Self>> {
        let uri = match std::env::var("NEO4J_URI") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                tracing::info!("NEO4J_URI not set — Graph RAG disabled");
                return Ok(None);
            }
        };
        // MCP-631: empty-env hardening — `NEO4J_USER=""` (Helm
        // placeholder) would otherwise yield empty creds and Neo4j
        // would fail to connect with a generic auth error rather than
        // using the documented default. Sibling to MCP-630.
        let user = std::env::var("NEO4J_USER")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "neo4j".to_string());
        let password = match std::env::var("NEO4J_PASSWORD") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                tracing::error!(
                    "NEO4J_PASSWORD not set — refusing to connect with default credentials. \
                     Set NEO4J_PASSWORD in your environment or .env file."
                );
                return Ok(None);
            }
        };

        let config = neo4rs::ConfigBuilder::default()
            .uri(&uri)
            .user(&user)
            .password(&password)
            .max_connections(10)
            .build()
            .context("Failed to build Neo4j config")?;

        let graph = neo4rs::Graph::connect(config)
            .await
            .context("Failed to connect to Neo4j")?;

        let service = Self {
            graph: Arc::new(graph),
            secrets: None,
            actor_repo: None,
        };
        service.init_schema().await?;

        tracing::info!(uri = %uri, "Graph RAG service connected to Neo4j");
        Ok(Some(service))
    }

    /// Access the underlying Neo4j graph for direct Cypher queries
    /// from MCP handlers. Callers MUST enforce actor_id isolation in
    /// their queries.
    pub fn graph_ref(&self) -> &neo4rs::Graph {
        &self.graph
    }

    /// Test-only constructor for exercising the PURE extraction paths
    /// (`extract_triples_rule_based`, which is `&self` but touches no
    /// network state for the shapes under test) without a live Neo4j.
    /// `neo4rs::Graph::connect` builds a deadpool that only dials on the
    /// first `.run()`/`.execute()`, and these tests never issue one — so
    /// no database is required. Mirrors the
    /// `SecretsManager::test_stub_for_cache` pattern: a real struct whose
    /// I/O handle panics only if actually driven.
    #[cfg(test)]
    pub(crate) async fn test_stub_without_neo4j() -> Self {
        let config = neo4rs::ConfigBuilder::default()
            .uri("bolt://127.0.0.1:7687")
            .user("neo4j")
            .password("test-stub-never-dialed")
            .max_connections(1)
            .build()
            .expect("test stub: failed to build neo4rs config");
        // `connect` only builds the lazy deadpool — no socket is opened
        // until the first query, which these tests never issue.
        let graph = neo4rs::Graph::connect(config)
            .await
            .expect("test stub: failed to build lazy neo4rs pool");
        Self {
            graph: Arc::new(graph),
            secrets: None,
            actor_repo: None,
        }
    }

    /// Create indexes and constraints for the knowledge graph schema.
    async fn init_schema(&self) -> Result<()> {
        let constraints = [
            // Uniqueness: one node per (actor_id, name, label) triple.
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Person) REQUIRE (p.actor_id, p.name) IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Ticket) REQUIRE (t.actor_id, t.name) IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Project) REQUIRE (p.actor_id, p.name) IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Concept) REQUIRE (c.actor_id, c.name) IS UNIQUE",
            // Full-text index for entity search across all labels.
            "CREATE FULLTEXT INDEX entity_name_fulltext IF NOT EXISTS FOR (n:Person|Ticket|Project|Concept|Meeting|Email) ON EACH [n.name]",
        ];
        for cypher in constraints {
            if let Err(e) = self.graph.run(neo4rs::query(cypher)).await {
                tracing::warn!(cypher, error = %e, "Neo4j schema init warning (may be expected on first run)");
            }
        }
        Ok(())
    }

    /// Extract entities and relationships from a memory value using LLM,
    /// then store them in Neo4j.
    ///
    /// This is the write path — called from `persist_memory` after the
    /// memory is stored in Postgres. The extraction is best-effort:
    /// failures don't block the memory write.
    pub async fn extract_and_store_entities(
        &self,
        actor_id: Uuid,
        memory_key: &str,
        memory_value: &serde_json::Value,
    ) -> Result<usize> {
        // Serialize the memory value to a compact string for the LLM.
        let value_str = serde_json::to_string(memory_value)
            .unwrap_or_default()
            .chars()
            .take(4000)
            .collect::<String>();

        if value_str.len() < 20 {
            return Ok(0); // Too short to extract meaningful entities.
        }

        // Try rule-based extraction first (free, fast, handles known shapes).
        // Only fall back to LLM when rule-based returns empty AND the API key
        // is available. This avoids unnecessary LLM calls for the common case
        // (Jira tickets, email triage) while still handling unknown shapes.
        let mut triples = self.extract_triples_rule_based(memory_key, memory_value);

        if triples.is_empty() {
            // Tier-1 data-egress gate. Tier1 actors are policy-bound
            // to keep data on-host (local Ollama only) — sending
            // their memory contents to Anthropic for triple
            // extraction would violate that ceiling, even though
            // graph-RAG itself is best-effort. Fail closed: if the
            // tier lookup errors, treat as Tier1 and skip — same
            // contract as `talos_engine::actor_binding::apply_actor_to_engine`.
            // When `actor_repo` is unset (e.g. unit tests), legacy
            // un-gated behaviour applies.
            if !self.actor_allows_external_llm(actor_id).await {
                tracing::debug!(
                    target: "talos_graph_rag",
                    actor_id = %actor_id,
                    memory_key,
                    "Skipped LLM entity extraction: actor max_llm_tier=tier1 (or tier lookup failed) — data may not leave host"
                );
                return Ok(0);
            }

            // Resolve the Anthropic key with vault-first preference,
            // env fallback. In vault-first deployments
            // (`set_secret anthropic/api_key`), the env var isn't set
            // and the original env-only path silently no-op'd —
            // `graph_stats` came back empty even though the actor was
            // accumulating memories. Both sources tolerate placeholder
            // strings ("your-api-key-here", "") so dev setups don't
            // burn HTTP 401s.
            let api_key = self.resolve_anthropic_key().await;
            if let Some(key) = api_key {
                match self
                    .extract_triples_via_llm(&key, memory_key, &value_str)
                    .await
                {
                    Ok(llm_triples) => triples = llm_triples,
                    Err(e) => {
                        tracing::warn!(
                            target: "talos_graph_rag",
                            memory_key,
                            error = %e,
                            "LLM entity extraction failed — graph row will have no \
                             relationships. Common causes: anthropic/api_key invalid \
                             or revoked (HTTP 401), rate limit (HTTP 429), or model \
                             deprecation."
                        );
                    }
                }
            } else {
                tracing::debug!(
                    target: "talos_graph_rag",
                    memory_key,
                    "Skipped LLM entity extraction: no anthropic/api_key in vault \
                     and ANTHROPIC_API_KEY env missing/placeholder. Set the vault \
                     path to enable graph extraction, or ignore — actor_memory \
                     writes still succeed without it."
                );
            }
        }

        if triples.is_empty() {
            return Ok(0);
        }

        let count = triples.len();
        // Batched upsert: instead of one Neo4j round-trip per triple
        // (the old N+1 — ~80 sequential MERGEs on an 80-issue Jira
        // sync), group triples by their (subject_label, object_label,
        // predicate) tuple — the only parts of the Cypher that can't be
        // parameterized — and emit ONE `UNWIND $rows AS t MERGE ...`
        // query per group (typically 1-3 groups). MERGE semantics are
        // byte-for-byte identical to the per-row version.
        self.upsert_triples(actor_id, memory_key, &triples).await?;

        tracing::debug!(
            actor_id = %actor_id,
            memory_key,
            triples = count,
            "Graph entities extracted and stored"
        );
        Ok(count)
    }

    /// Rule-based entity extraction for known memory value shapes.
    ///
    /// Handles the common cases (Jira issues, email classifications,
    /// meeting preps) without an LLM call. Falls back gracefully for
    /// unknown shapes (returns empty).
    fn extract_triples_rule_based(
        &self,
        memory_key: &str,
        value: &serde_json::Value,
    ) -> Vec<Triple> {
        let mut triples = Vec::new();
        let data = value.get("data").unwrap_or(value);

        match memory_key {
            "jira_work_context" | "ticket_classification" => {
                // Extract tickets from ALL Jira status categories.
                let arrays = [
                    "issues",
                    "classified_tickets",
                    "in_progress",
                    "to_do",
                    "in_review",
                    "done_today",
                    "still_pending",
                ];
                let mut all_issues: Vec<&serde_json::Value> = Vec::new();
                for field in &arrays {
                    if let Some(arr) = data.get(*field).and_then(|v| v.as_array()) {
                        all_issues.extend(arr.iter());
                    }
                }
                for issue in &all_issues {
                    let key = issue
                        .get("key")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let summary = issue
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let assignee = issue
                        .get("assignee")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let status = issue
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();

                    if !key.is_empty() {
                        triples.push(Triple {
                            subject: Entity {
                                label: "Ticket".to_string(),
                                name: key.to_string(),
                                properties: vec![
                                    ("summary".to_string(), summary.to_string()),
                                    ("status".to_string(), status.to_string()),
                                ],
                            },
                            predicate: "ASSIGNED_TO".to_string(),
                            object: Entity {
                                label: "Person".to_string(),
                                name: if assignee.is_empty() {
                                    "Unassigned".to_string()
                                } else {
                                    assignee.to_string()
                                },
                                properties: vec![],
                            },
                        });
                    }
                }
            }
            "email_triage" | "email_drafts" => {
                // Extract people from email triage results.
                for category in &[
                    "needs_response",
                    "actionable",
                    "security_alerts",
                    "fyi",
                    "noise",
                ] {
                    if let Some(items) = data.get(*category).and_then(|v| v.as_array()) {
                        for item in items {
                            let from = item
                                .get("from")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            let subject = item
                                .get("subject")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();

                            if !from.is_empty() && !subject.is_empty() {
                                triples.push(Triple {
                                    subject: Entity {
                                        label: "Person".to_string(),
                                        name: from.to_string(),
                                        properties: vec![],
                                    },
                                    predicate: "DISCUSSED_IN".to_string(),
                                    object: Entity {
                                        label: "Email".to_string(),
                                        name: subject.chars().take(100).collect(),
                                        properties: vec![(
                                            "category".to_string(),
                                            category.to_string(),
                                        )],
                                    },
                                });
                            }
                        }
                    }
                }
            }
            "meeting_preps" => {
                if let Some(preps) = data.get("preps").and_then(|v| v.as_array()) {
                    for prep in preps {
                        let summary = prep
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if !summary.is_empty() {
                            triples.push(Triple {
                                subject: Entity {
                                    label: "Meeting".to_string(),
                                    name: summary.to_string(),
                                    properties: vec![],
                                },
                                predicate: "RELATED_TO".to_string(),
                                object: Entity {
                                    label: "Concept".to_string(),
                                    name: "meeting_prep".to_string(),
                                    properties: vec![],
                                },
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        // Bound the rule-based path. The Jira issue loop above is
        // otherwise UNCAPPED — a large sync (e.g. an 80+ issue board)
        // would emit one MERGE round-trip per issue on every memory
        // write. Truncate to `MAX_RULE_BASED_TRIPLES` and log loudly so
        // operators can see when a sync is being clipped (CLAUDE.md:
        // "no silent caps").
        if triples.len() > MAX_RULE_BASED_TRIPLES {
            tracing::warn!(
                target: "talos_graph_rag",
                memory_key,
                extracted = triples.len(),
                cap = MAX_RULE_BASED_TRIPLES,
                "Rule-based triple extraction exceeded the per-write cap — \
                 truncating. The graph will reflect only the first {} \
                 relationships from this memory write.",
                MAX_RULE_BASED_TRIPLES
            );
            triples.truncate(MAX_RULE_BASED_TRIPLES);
        }

        triples
    }

    /// Tier-1 data-egress gate for the LLM-fallback extraction
    /// path. Returns `true` when LLM extraction is permitted for
    /// `actor_id`:
    ///   * No `actor_repo` wired in → legacy un-gated behaviour
    ///     (the controller has explicitly opted out of tier
    ///     enforcement; usually means the deployment doesn't have
    ///     tier-1 actors at all).
    ///   * `actor_repo` returns `Tier2` → permitted.
    ///   * `actor_repo` returns `Tier1` → BLOCKED (tier1 = local
    ///     only, must not egress to Anthropic).
    ///   * `actor_repo` returns `Ok(None)` (actor row missing) →
    ///     BLOCKED. A memory write referencing a missing actor is
    ///     unusual; fail closed rather than leak data.
    ///   * `actor_repo` returns `Err(...)` → BLOCKED (DB error;
    ///     fail closed). Same contract as
    ///     `talos_engine::actor_binding::apply_actor_to_engine`.
    async fn actor_allows_external_llm(&self, actor_id: Uuid) -> bool {
        let Some(repo) = &self.actor_repo else {
            // Legacy path — caller didn't wire in the repo, so don't
            // gate. This preserves the pre-tier behaviour for
            // deployments that haven't migrated.
            return true;
        };
        match repo.get_actor_max_llm_tier(actor_id).await {
            Ok(Some(talos_workflow_job_protocol::LlmTier::Tier2)) => true,
            // `LlmTier` is non-exhaustive (per upstream); only Tier2
            // is permitted, anything else (Tier1 or any future
            // stricter variant) fails closed.
            Ok(Some(_)) => false,
            Ok(None) => {
                tracing::warn!(
                    target: "talos_graph_rag",
                    actor_id = %actor_id,
                    "Actor not found during tier check — failing closed (Tier1)"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_graph_rag",
                    actor_id = %actor_id,
                    error = %e,
                    "Tier lookup failed — failing closed (Tier1)"
                );
                false
            }
        }
    }

    /// Resolve the Anthropic API key for graph-RAG's LLM-fallback
    /// extraction. Vault first when a `SecretsManager` is wired in
    /// (`with_secrets`), env second. Both sources are filtered for
    /// placeholder strings ("your-api-key-here", "") so dev setups
    /// don't burn HTTP 401s on every extraction. Returns `None` when
    /// no usable key is available — the caller logs at debug and
    /// skips extraction without failing the memory write.
    ///
    /// Returns `Zeroizing<String>` (not plain `String`) so the
    /// plaintext bytes are wiped from heap when the value drops.
    /// This matches `LlmClient::resolve_api_key`'s wiped-on-drop
    /// guarantee — the key flows into one reqwest header for one
    /// HTTP call and is dropped, bounding the heap-exposure window
    /// to the request lifetime.
    async fn resolve_anthropic_key(&self) -> Option<talos_secrets_manager::Zeroizing<String>> {
        if let Some(sm) = &self.secrets {
            // None scope — controller-side LLM keys live under the
            // platform's trust boundary, not a specific end-user.
            // Same scoping as `LlmClient::with_vault`.
            match sm.get_llm_vault_keys(None).await {
                Ok(map) => {
                    if let Some(v) = map.get("anthropic/api_key") {
                        // Clone preserves the `Zeroizing` wrapper, so
                        // the plaintext is wiped on drop down the
                        // chain — same property `LlmClient` provides.
                        if !is_placeholder_key(v.as_str()) {
                            return Some(v.clone());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "talos_graph_rag",
                        error = %e,
                        "vault lookup failed for anthropic/api_key — falling back to env"
                    );
                }
            }
        }
        std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|k| !is_placeholder_key(k))
            .map(talos_secrets_manager::Zeroizing::new)
    }

    /// LLM-based entity extraction using Anthropic's structured output.
    async fn extract_triples_via_llm(
        &self,
        api_key: &str,
        memory_key: &str,
        value_str: &str,
    ) -> Result<Vec<Triple>> {
        let prompt = format!(
            "Extract entities and relationships from this data. \
             Context: this is a '{}' memory from a personal work assistant.\n\n\
             Data:\n{}\n\n\
             Return a JSON array of triples. Each triple has:\n\
             - subject: {{label: \"Person\"|\"Ticket\"|\"Project\"|\"Email\"|\"Meeting\"|\"Concept\", name: \"...\"}}\n\
             - predicate: \"WORKS_ON\"|\"ASSIGNED_TO\"|\"DISCUSSED_IN\"|\"ATTENDED\"|\"RELATED_TO\"|\"MENTIONED_IN\"|\"BLOCKED_BY\"|\"CREATED\"\n\
             - object: {{label: \"...\", name: \"...\"}}\n\n\
             Only extract clear, factual relationships. Return [] if nothing extractable. Maximum 20 triples.",
            memory_key, value_str
        );

        // MCP-497: same hardened-build-or-fail as MCP-496. This client
        // posts to api.anthropic.com with `x-api-key` — a custom
        // header that reqwest does NOT strip on cross-origin redirect.
        // A 302 from api.anthropic.com (MITM'd or via a future URL
        // change) would carry the Anthropic API key to wherever the
        // redirect points. `Client::new()` re-enables the default
        // 10-hop redirect policy.
        // MCP-1058 (2026-05-15): pair `.timeout()` with
        // `.connect_timeout()`. Triple-extractor posts to
        // api.anthropic.com — a stalled TLS handshake would otherwise
        // consume the full 30s budget before bailing.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("graph-rag triple-extractor: failed to build hardened reqwest client");

        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [{
                "name": "extract_triples",
                "description": "Extract entity-relationship triples",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "triples": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "subject_label": {"type": "string"},
                                    "subject_name": {"type": "string"},
                                    "predicate": {"type": "string"},
                                    "object_label": {"type": "string"},
                                    "object_name": {"type": "string"}
                                },
                                "required": ["subject_label", "subject_name", "predicate", "object_label", "object_name"]
                            }
                        }
                    },
                    "required": ["triples"]
                }
            }],
            "tool_choice": {"type": "tool", "name": "extract_triples"}
        });

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("LLM extraction request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("LLM extraction returned HTTP {}", resp.status());
        }

        let response: serde_json::Value = talos_http_body::read_json_capped(resp).await?;
        let tool_input = response
            .get("content")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("input"))
            .and_then(|i| i.get("triples"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        let triples: Vec<Triple> = tool_input
            .iter()
            .filter_map(|t| {
                Some(Triple {
                    subject: Entity {
                        label: t.get("subject_label")?.as_str()?.to_string(),
                        name: t.get("subject_name")?.as_str()?.to_string(),
                        properties: vec![],
                    },
                    predicate: t.get("predicate")?.as_str()?.to_string(),
                    object: Entity {
                        label: t.get("object_label")?.as_str()?.to_string(),
                        name: t.get("object_name")?.as_str()?.to_string(),
                        properties: vec![],
                    },
                })
            })
            .take(20) // Cap to prevent runaway extraction
            .collect();

        Ok(triples)
    }

    /// Batched upsert of triples into Neo4j.
    ///
    /// Replaces the old per-triple N+1 (`upsert_triple` in a loop —
    /// one `graph.run()` MERGE round-trip per triple, so an 80-issue
    /// Jira sync was ~80 sequential round-trips on every memory write).
    ///
    /// Neo4j node labels and relationship types can NOT be bound as
    /// `$params` — they're structural Cypher. So we group triples by
    /// their `(subject_label, object_label, predicate)` tuple (the only
    /// parts that vary the query text) and emit ONE
    /// `UNWIND $rows AS t MERGE ...` query per group — typically 1-3
    /// groups for a real workload — binding the per-row names/source/ts
    /// as `$rows` parameters. N round-trips collapse to
    /// number-of-groups. The per-row MERGE inside the UNWIND uses the
    /// identical match keys (`{actor_id, name}`) and the identical
    /// SET-both-on-create-and-match behaviour as the old single-triple
    /// path, so the graph result is byte-for-byte the same.
    async fn upsert_triples(
        &self,
        actor_id: Uuid,
        source_key: &str,
        triples: &[Triple],
    ) -> Result<()> {
        if triples.is_empty() {
            return Ok(());
        }
        let actor_str = actor_id.to_string();
        let now = chrono::Utc::now().to_rfc3339();

        for group in group_triples_for_upsert(triples) {
            // Build the `$rows` list parameter: one map per triple in
            // this group, carrying just the parameterizable values.
            let mut rows = neo4rs::BoltList::new();
            for row in &group.rows {
                let mut m = neo4rs::BoltMap::default();
                m.put("subject_name".into(), row.subject_name.as_str().into());
                m.put("object_name".into(), row.object_name.as_str().into());
                // Sanitized, bound property maps consumed by
                // `SET s/o += t.*_props`. Empty maps are no-ops.
                m.put(
                    "subject_props".into(),
                    neo4rs::BoltType::Map(build_property_bolt_map(&row.subject_props)),
                );
                m.put(
                    "object_props".into(),
                    neo4rs::BoltType::Map(build_property_bolt_map(&row.object_props)),
                );
                rows.push(neo4rs::BoltType::Map(m));
            }

            let q = neo4rs::query(&group.cypher)
                .param("actor_id", actor_str.as_str())
                .param("source_key", source_key)
                .param("now", now.as_str())
                .param("rows", neo4rs::BoltType::List(rows));

            self.graph
                .run(q)
                .await
                .context("Neo4j batched upsert failed")?;
        }
        Ok(())
    }

    /// Retrieve graph context for a query by finding matching entities
    /// and traversing 1-2 hops to related nodes.
    ///
    /// Returns a structured JSON representation of the subgraph that
    /// the LLM can use alongside vector-retrieved memories.
    pub async fn get_graph_context(
        &self,
        actor_id: Uuid,
        query: &str,
        max_hops: usize,
        max_nodes: usize,
    ) -> Result<serde_json::Value> {
        let actor_str = actor_id.to_string();
        let hops = max_hops.min(3) as i64; // Cap at 3 to prevent expensive traversals
        let limit = max_nodes.min(50) as i64;

        // Build a Lucene fulltext query that handles hyphenated identifiers
        // (e.g., "SECP-11779"). Lucene tokenizes on hyphens, so "SECP-11779"
        // becomes tokens ["SECP", "11779"]. We search for each token with a
        // wildcard suffix so partial matches work, AND we do an exact-match
        // fallback via `WHERE n.name = $exact` for cases where the fulltext
        // index can't match (e.g., single hyphenated tokens tokenized away).
        let escaped = escape_lucene(query);
        let wildcard_query = format!(
            "{}*",
            escaped.split_whitespace().collect::<Vec<_>>().join("* ")
        );

        // Also build a query from the raw alphanumeric parts of each word.
        // "SECP-11779" → "SECP* 11779*" which matches the tokenized index.
        let token_query: String = query
            .split_whitespace()
            .flat_map(|word| {
                word.split(|c: char| !c.is_ascii_alphanumeric())
                    .filter(|t| !t.is_empty())
                    .map(|t| format!("{}*", escape_lucene(t)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .join(" ");

        // Prefer the token query (handles hyphens), fall back to wildcard.
        let search_query = if token_query != wildcard_query && !token_query.is_empty() {
            token_query
        } else {
            wildcard_query
        };

        let cypher = format!(
            "CALL db.index.fulltext.queryNodes('entity_name_fulltext', $query) \
             YIELD node, score \
             WHERE node.actor_id = $actor_id \
             WITH node, score \
             ORDER BY score DESC LIMIT 10 \
             CALL apoc.path.subgraphAll(node, {{maxLevel: {}, limit: {}}}) \
             YIELD nodes, relationships \
             UNWIND nodes AS n \
             WITH DISTINCT n \
             WHERE n.actor_id = $actor_id \
             RETURN labels(n) AS labels, n.name AS name, \
                    [(n)-[r]->(m) WHERE m.actor_id = $actor_id | \
                     {{type: type(r), target: m.name, target_labels: labels(m)}}] AS rels \
             LIMIT $limit",
            hops, limit
        );

        let mut result = self
            .graph
            .execute(
                neo4rs::query(&cypher)
                    .param("query", search_query.as_str())
                    .param("actor_id", actor_str.as_str())
                    .param("limit", limit),
            )
            .await
            .context("Neo4j graph context query failed")?;

        let mut entities: Vec<serde_json::Value> = Vec::new();
        while let Ok(Some(row)) = result.next().await {
            let labels: Vec<String> = row.get("labels").unwrap_or_default();
            let name: String = row.get("name").unwrap_or_default();
            let rels: Vec<serde_json::Value> = row.get("rels").unwrap_or_default();

            entities.push(serde_json::json!({
                "type": labels.first().unwrap_or(&"Unknown".to_string()),
                "name": name,
                "relationships": rels,
            }));
        }

        // Fallback: if fulltext returned nothing, try exact name match.
        // This handles edge cases where the fulltext index tokenization
        // completely misses the query (e.g., very short tokens, special chars).
        if entities.is_empty() {
            let exact_cypher = format!(
                "MATCH (node {{actor_id: $actor_id, name: $exact}}) \
                 WITH node \
                 LIMIT 5 \
                 CALL apoc.path.subgraphAll(node, {{maxLevel: {}, limit: {}}}) \
                 YIELD nodes, relationships \
                 UNWIND nodes AS n \
                 WITH DISTINCT n \
                 WHERE n.actor_id = $actor_id \
                 RETURN labels(n) AS labels, n.name AS name, \
                        [(n)-[r]->(m) WHERE m.actor_id = $actor_id | \
                         {{type: type(r), target: m.name, target_labels: labels(m)}}] AS rels \
                 LIMIT $limit",
                hops, limit
            );

            let mut fallback = self
                .graph
                .execute(
                    neo4rs::query(&exact_cypher)
                        .param("actor_id", actor_str.as_str())
                        .param("exact", query)
                        .param("limit", limit),
                )
                .await
                .context("Neo4j exact match fallback failed")?;

            while let Ok(Some(row)) = fallback.next().await {
                let labels: Vec<String> = row.get("labels").unwrap_or_default();
                let name: String = row.get("name").unwrap_or_default();
                let rels: Vec<serde_json::Value> = row.get("rels").unwrap_or_default();

                entities.push(serde_json::json!({
                    "type": labels.first().unwrap_or(&"Unknown".to_string()),
                    "name": name,
                    "relationships": rels,
                }));
            }
        }

        Ok(serde_json::json!({
            "entities": entities,
            "entity_count": entities.len(),
            "query": query,
        }))
    }

    /// Get graph statistics for the hygiene report.
    pub async fn get_stats(&self, actor_id: Uuid) -> Result<serde_json::Value> {
        let actor_str = actor_id.to_string();
        let mut result = self
            .graph
            .execute(
                neo4rs::query(
                    "MATCH (n {actor_id: $actor_id}) \
                     RETURN labels(n)[0] AS label, count(n) AS count \
                     ORDER BY count DESC",
                )
                .param("actor_id", actor_str.as_str()),
            )
            .await?;

        let mut node_counts: Vec<serde_json::Value> = Vec::new();
        while let Ok(Some(row)) = result.next().await {
            let label: String = row.get("label").unwrap_or_default();
            let count: i64 = row.get("count").unwrap_or(0);
            node_counts.push(serde_json::json!({"label": label, "count": count}));
        }

        let mut edge_result = self
            .graph
            .execute(
                neo4rs::query(
                    "MATCH ({actor_id: $actor_id})-[r]->({actor_id: $actor_id}) \
                     RETURN type(r) AS type, count(r) AS count \
                     ORDER BY count DESC",
                )
                .param("actor_id", actor_str.as_str()),
            )
            .await?;

        let mut edge_counts: Vec<serde_json::Value> = Vec::new();
        while let Ok(Some(row)) = edge_result.next().await {
            let rtype: String = row.get("type").unwrap_or_default();
            let count: i64 = row.get("count").unwrap_or(0);
            edge_counts.push(serde_json::json!({"type": rtype, "count": count}));
        }

        Ok(serde_json::json!({
            "nodes": node_counts,
            "edges": edge_counts,
        }))
    }
}

/// Upper bound on triples emitted by `extract_triples_rule_based` per
/// memory write. The LLM extraction path is already bounded ("Maximum
/// 20 triples" in the prompt + `.take(20)` on the response), but the
/// rule-based Jira path (`jira_work_context` / `ticket_classification`)
/// iterated ALL issues across every status array with no cap — an
/// 80-issue sync produced ~80 triples, and each was a separate Neo4j
/// MERGE round-trip on every write (P3 finding). We bound the
/// rule-based path to the same order of magnitude as the LLM path but
/// a bit higher (a single Jira sync can legitimately carry more than 20
/// real tickets). 200 covers realistic sprint/board sizes while
/// guaranteeing the batched upsert can't be handed unbounded work from
/// a hostile or runaway upstream. Truncation is logged (no silent cap).
const MAX_RULE_BASED_TRIPLES: usize = 200;

/// An entity node in the knowledge graph.
#[derive(Debug, Clone)]
struct Entity {
    label: String,
    name: String,
    // Extra key/value properties populated at extract time (e.g.
    // Ticket.summary/status, Email.category — see the `triples.push`
    // sites in `extract_triples_rule_based`). These ARE persisted onto
    // the node (resolved MCP-953 deferral): `upsert_triples` threads them
    // through the batched MERGE as a parameterized map and applies
    // `SET n += t.props`. Because the map is a *bound parameter*, property
    // keys arrive as data — never interpolated into Cypher text — so
    // Cypher injection is structurally impossible. The residual risk of a
    // bound map is *reserved-key overwrite* (a property literally named
    // `actor_id` would move the node into another tenant's namespace), so
    // `sanitize_property_key` drops the reserved structural keys and
    // charset-normalizes the rest. Keys are user/LLM-derived; values are
    // length-capped.
    properties: Vec<(String, String)>,
}

/// A subject-predicate-object triple.
#[derive(Debug, Clone)]
struct Triple {
    subject: Entity,
    predicate: String,
    object: Entity,
}

/// One parameterizable row inside an UNWIND batch — just the values
/// that vary per triple within a single `(subject_label, object_label,
/// predicate)` group. Labels/predicate are baked into the group's
/// Cypher text (they can't be `$params`), so they're not repeated here.
///
/// `subject_props`/`object_props` carry the entities' extra properties
/// verbatim (raw, unsanitized) so the grouping logic stays a pure,
/// easily-tested transform; sanitization (`sanitize_property_key` +
/// value-length cap) is applied at BoltMap-build time in `upsert_triples`,
/// right before the values cross into Neo4j as a bound `$rows` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpsertRow {
    subject_name: String,
    object_name: String,
    subject_props: Vec<(String, String)>,
    object_props: Vec<(String, String)>,
}

/// A group of triples that share the same `(subject_label,
/// object_label, predicate)` tuple and therefore the same Cypher
/// structure. Upserted in ONE `UNWIND $rows AS t MERGE ...` round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpsertGroup {
    cypher: String,
    rows: Vec<UpsertRow>,
}

/// Pure helper (no Neo4j, no I/O) that turns a flat list of triples
/// into the minimal set of batched-upsert groups.
///
/// Neo4j labels and relationship types are structural — they can NOT
/// be bound as `$params`. Everything else (the subject/object `name`,
/// `source_key`, `updated_at`) CAN. So we key each group on the
/// SANITIZED `(subject_label, object_label, predicate)` tuple (sanitize
/// FIRST so two raw labels that normalize to the same canonical label
/// share a group and so the key matches the emitted Cypher exactly),
/// and within a group every triple becomes one `$rows` entry.
///
/// The emitted Cypher per group is the UNWIND form of the original
/// single-triple MERGE — identical match keys (`{actor_id, name}`) and
/// identical SET-on-both-create-and-match behaviour — so the resulting
/// graph is the same as the old per-triple loop, just in 1-3 round
/// trips instead of N.
///
/// Insertion order is preserved (first-seen group ordering, and row
/// order within a group) so behaviour is deterministic and the
/// last-writer-wins semantics of MERGE+SET match the old sequential
/// loop for duplicate (subject, predicate, object) entries.
fn group_triples_for_upsert(triples: &[Triple]) -> Vec<UpsertGroup> {
    // (sanitized_subject_label, sanitized_object_label, sanitized_predicate)
    // -> index into `groups`. Preserves first-seen ordering.
    let mut index: std::collections::HashMap<(String, String, String), usize> =
        std::collections::HashMap::new();
    let mut groups: Vec<UpsertGroup> = Vec::new();

    for triple in triples {
        let s_label = sanitize_label(&triple.subject.label);
        let o_label = sanitize_label(&triple.object.label);
        let pred = sanitize_label(&triple.predicate);

        let key = (s_label.clone(), o_label.clone(), pred.clone());
        let idx = *index.entry(key).or_insert_with(|| {
            groups.push(UpsertGroup {
                cypher: build_unwind_upsert_cypher(&s_label, &o_label, &pred),
                rows: Vec::new(),
            });
            groups.len() - 1
        });
        groups[idx].rows.push(UpsertRow {
            subject_name: triple.subject.name.clone(),
            object_name: triple.object.name.clone(),
            subject_props: triple.subject.properties.clone(),
            object_props: triple.object.properties.clone(),
        });
    }

    groups
}

/// Build the per-group batched MERGE. Labels/predicate are already
/// sanitized by the caller (allowlisted canonical tokens — never raw
/// input — so they're safe in the un-parameterizable label position;
/// see `sanitize_label` + `sanitize_label_tests`). `$rows` is a list of
/// `{subject_name, object_name, subject_props, object_props}` maps;
/// `$actor_id`, `$source_key`, `$now` are scalars shared across the whole
/// batch.
///
/// `SET s += t.subject_props` applies the entity's extra properties from a
/// *bound map* — keys arrive as data, so this can't inject Cypher. It is
/// emitted BEFORE the structural `SET s.source_key/updated_at` so the
/// provenance columns always win even if a property key collided with one
/// (defense in depth; `sanitize_property_key` already drops the reserved
/// keys). An empty props map makes `SET s += {}` a harmless no-op.
fn build_unwind_upsert_cypher(subject_label: &str, object_label: &str, predicate: &str) -> String {
    format!(
        "UNWIND $rows AS t \
         MERGE (s:{subject_label} {{actor_id: $actor_id, name: t.subject_name}}) \
         SET s += t.subject_props \
         SET s.source_key = $source_key, s.updated_at = $now \
         MERGE (o:{object_label} {{actor_id: $actor_id, name: t.object_name}}) \
         SET o += t.object_props \
         SET o.source_key = $source_key, o.updated_at = $now \
         MERGE (s)-[r:{predicate}]->(o) \
         SET r.source_key = $source_key, r.updated_at = $now"
    )
}

/// Escape Lucene special characters in a fulltext query string.
///
/// Neo4j's fulltext indexes use Lucene under the hood. Even though the
/// query is passed via a Cypher `$query` parameter (preventing Cypher
/// injection), the parameter value is interpreted as a Lucene query
/// string. Special characters can manipulate boolean logic, field
/// targeting, and wildcard expansion.
fn escape_lucene(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        // Escape single-char operators AND the components of two-char
        // operators (&& and ||). Escaping each & and | individually
        // produces \&\& and \|\| which neutralizes the boolean operators.
        if matches!(
            c,
            '+' | '-'
                | '&'
                | '|'
                | '!'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '^'
                | '"'
                | '~'
                | '*'
                | '?'
                | ':'
                | '\\'
                | '/'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Known entity labels. Labels from LLM extraction are validated against
/// this list — unknown labels map to "Concept" to prevent uncontrolled
/// node type proliferation. This also prevents Cypher injection via
/// labels that start with digits or contain special characters.
const ALLOWED_NODE_LABELS: &[&str] = &[
    "Person",
    "Ticket",
    "Project",
    "Email",
    "Meeting",
    "Concept",
    "Organization",
    "Service",
    "Repository",
    "Document",
];

const ALLOWED_EDGE_TYPES: &[&str] = &[
    "WORKS_ON",
    "ASSIGNED_TO",
    "DISCUSSED_IN",
    "ATTENDED",
    "RELATED_TO",
    "MENTIONED_IN",
    "BLOCKED_BY",
    "CREATED",
    "OWNS",
    "REPORTS_TO",
];

/// Validate and sanitize a label for use in Cypher. Node labels must be
/// in the allowlist; unknown labels map to "Concept". Edge types must be
/// in the edge allowlist; unknown types map to "RELATED_TO".
fn sanitize_label(label: &str) -> String {
    // Check node labels first, then edge types.
    let normalized: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if ALLOWED_NODE_LABELS
        .iter()
        .any(|&l| l.eq_ignore_ascii_case(&normalized))
    {
        // Return the canonical casing from the allowlist.
        ALLOWED_NODE_LABELS
            .iter()
            .find(|&&l| l.eq_ignore_ascii_case(&normalized))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Concept".to_string())
    } else if ALLOWED_EDGE_TYPES
        .iter()
        .any(|&t| t.eq_ignore_ascii_case(&normalized))
    {
        ALLOWED_EDGE_TYPES
            .iter()
            .find(|&&t| t.eq_ignore_ascii_case(&normalized))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "RELATED_TO".to_string())
    } else {
        // Unknown label from LLM → map to Concept (nodes) or RELATED_TO (edges).
        // Determine by convention: all-caps with underscores = edge, otherwise = node.
        if normalized
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_')
            && normalized.contains('_')
        {
            "RELATED_TO".to_string()
        } else {
            "Concept".to_string()
        }
    }
}

/// Structural property keys that MUST NOT be settable from extracted
/// entity properties. `actor_id` is the tenant boundary (overwriting it
/// would move the node into another actor's subgraph); `name` is the
/// MERGE identity; `source_key`/`updated_at` are provenance written by
/// the upsert itself. A `SET n += $props` with a bound map can't inject
/// Cypher, but it CAN clobber these if the map carries them — so they're
/// dropped here (case-insensitive, after charset normalization).
const RESERVED_PROPERTY_KEYS: &[&str] = &["actor_id", "name", "source_key", "updated_at"];

/// Max sanitized property-key length. Neo4j has no hard limit, but a
/// bound keeps a hostile/runaway extractor from minting absurd keys.
const MAX_PROPERTY_KEY_LEN: usize = 64;

/// Max stored property-value length (chars). Values are bound `$params`
/// (injection-safe) but still need a size bound so a single property
/// can't bloat a node unboundedly.
const MAX_PROPERTY_VALUE_LEN: usize = 1024;

/// Max number of properties persisted per node. Caps total node width
/// regardless of how many (key,value) pairs the extractor emitted.
const MAX_PROPERTIES_PER_NODE: usize = 16;

/// Validate and sanitize a user/LLM-derived property key for safe Neo4j
/// persistence via `SET n += $props`. Returns `None` when the key must be
/// dropped.
///
/// Even though the property map is a bound parameter (so keys can't break
/// out into Cypher), an attacker-influenced key set still needs guarding
/// against *reserved-key overwrite*. The rules:
/// 1. Charset-normalize to `[A-Za-z0-9_]` (drop every other char).
/// 2. Reject empty / over-length results.
/// 3. Require a leading letter or `_` (Neo4j identifier shape; also bars
///    all-digit keys).
/// 4. Reject the reserved structural keys (tenant/identity/provenance).
fn sanitize_property_key(key: &str) -> Option<String> {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if normalized.is_empty() || normalized.len() > MAX_PROPERTY_KEY_LEN {
        return None;
    }
    let first = normalized.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    if RESERVED_PROPERTY_KEYS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(&normalized))
    {
        return None;
    }
    Some(normalized)
}

/// Apply `sanitize_property_key` + value-length cap + per-node count cap
/// to a raw `(key, value)` list, yielding the pairs actually persisted.
/// Last-writer-wins on keys that normalize to the same token (matches the
/// MERGE/SET last-write semantics for duplicate triples). Pure (no I/O)
/// so it's unit-tested directly.
fn sanitized_property_pairs(properties: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in properties {
        let Some(key) = sanitize_property_key(k) else {
            continue;
        };
        let val: String = v.chars().take(MAX_PROPERTY_VALUE_LEN).collect();
        if let Some(existing) = out.iter_mut().find(|(ek, _)| *ek == key) {
            existing.1 = val; // last-writer-wins
        } else {
            if out.len() >= MAX_PROPERTIES_PER_NODE {
                continue;
            }
            out.push((key, val));
        }
    }
    out
}

/// Build the bound `BoltMap` of sanitized properties for one node, ready
/// to drop into a `$rows` entry as `t.subject_props` / `t.object_props`.
/// An empty map makes the corresponding `SET n += {}` a no-op.
fn build_property_bolt_map(properties: &[(String, String)]) -> neo4rs::BoltMap {
    let mut m = neo4rs::BoltMap::default();
    for (key, val) in sanitized_property_pairs(properties) {
        m.put(key.into(), val.as_str().into());
    }
    m
}

/// Recognise common placeholder values for LLM API keys so the graph
/// extractor doesn't burn an HTTP call on a guaranteed 401. Covers the
/// shapes most often seen in fresh dev installs: empty, dummy text, and
/// truncated copy-paste fragments. A real Anthropic key is `sk-ant-`+
/// 95+ chars, so anything ≤ 20 chars is also rejected.
fn is_placeholder_key(k: &str) -> bool {
    let trimmed = k.trim();
    if trimmed.len() < 20 {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "your-api-key-here"
            | "your_api_key_here"
            | "placeholder"
            | "changeme"
            | "change-me"
            | "todo"
            | "<your-key>"
    ) || lower.starts_with("xxxx")
        || lower.starts_with("dummy")
        || lower.starts_with("example")
}

/// Process-wide singleton `GraphRagService`. Populated at controller
/// startup when Neo4j is configured (see `controller::main` for the
/// wiring). Pre-extraction this lived in
/// `controller::actor_memory_service::GRAPH_SERVICE`; moved here to
/// break the actor_memory_service ↔ workflow_repository import cycle
/// and to colocate it with the type it points at.
pub static GRAPH_SERVICE: std::sync::OnceLock<GraphRagService> = std::sync::OnceLock::new();

#[cfg(test)]
mod sanitize_label_tests {
    use super::sanitize_label;

    // `sanitize_label` is the ONLY guard between LLM-extracted (user-content-
    // derived) entity/relationship labels and the un-parameterizable Cypher
    // label/reltype position in `upsert_triple`. Cypher labels can't be bound
    // as `$params`, so a breakout here is graph injection (DETACH DELETE the
    // actor's whole subgraph, etc.). This pins the two layers of defense:
    // (1) the charset filter drops every Cypher-significant char, and
    // (2) the output is always an allowlisted label or a hardcoded default —
    // never the raw input.
    const CYPHER_BREAKOUT: &[&str] = &[
        "Person) DETACH DELETE n //",
        "Concept`) MATCH (x) DELETE x //",
        "Foo {actor_id: 1}) RETURN 1 //",
        "a-b; DROP",
        "rel]->(x)<-[:OWNS",
        "  spaces and (parens) ",
        "",
    ];

    #[test]
    fn sanitized_labels_carry_no_cypher_significant_chars() {
        for &raw in CYPHER_BREAKOUT {
            let out = sanitize_label(raw);
            assert!(
                out.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "sanitize_label({raw:?}) = {out:?} leaked a Cypher-significant char"
            );
            assert!(!out.is_empty(), "sanitize_label({raw:?}) must not be empty");
        }
    }

    #[test]
    fn unknown_labels_map_to_a_safe_default_not_the_raw_value() {
        // Node-shaped unknown → Concept; edge-shaped (ALL_CAPS_WITH_UNDERSCORE)
        // unknown → RELATED_TO. Either way, a fixed safe token — not user input.
        assert_eq!(sanitize_label("Person) DETACH DELETE n //"), "Concept");
        // Filters to "OWNS_RELDETACHDELETE" — all-caps with an underscore, so the
        // edge-shape heuristic maps it to RELATED_TO (still a fixed safe token).
        assert_eq!(sanitize_label("OWNS_REL DETACH DELETE"), "RELATED_TO");
    }
}

#[cfg(test)]
mod placeholder_tests {
    use super::is_placeholder_key;

    #[test]
    fn empty_is_placeholder() {
        assert!(is_placeholder_key(""));
        assert!(is_placeholder_key("   "));
    }

    #[test]
    fn short_is_placeholder() {
        // < 20 chars after trim — too short to be a real key.
        assert!(is_placeholder_key("sk-12345"));
    }

    #[test]
    fn known_placeholders_match() {
        assert!(is_placeholder_key("your-api-key-here"));
        assert!(is_placeholder_key("YOUR-API-KEY-HERE"));
        assert!(is_placeholder_key("placeholder"));
        assert!(is_placeholder_key("changeme"));
        assert!(is_placeholder_key("xxxx-real-looking-key-but-still-fake"));
    }

    #[test]
    fn long_realistic_key_passes() {
        // Real Anthropic keys start `sk-ant-...` and are ≥ 50 chars.
        assert!(!is_placeholder_key(
            "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}

/// Pure helper extracted so the tier-gate decision matrix is
/// testable without a real ActorRepository or Postgres. Mirrors
/// `actor_allows_external_llm` — keep both in sync if the policy
/// changes.
#[cfg(test)]
fn tier_decision_for_test(
    actor_repo_wired: bool,
    lookup: Option<Result<Option<talos_workflow_job_protocol::LlmTier>, ()>>,
) -> bool {
    if !actor_repo_wired {
        return true;
    }
    match lookup {
        Some(Ok(Some(talos_workflow_job_protocol::LlmTier::Tier2))) => true,
        // `LlmTier` is non-exhaustive — only Tier2 permits egress.
        Some(Ok(Some(_))) => false,
        Some(Ok(None)) => false, // missing actor — fail closed
        Some(Err(())) => false,  // DB error — fail closed
        None => false,           // shouldn't happen but fail closed
    }
}

#[cfg(test)]
mod tier_gate_tests {
    use super::tier_decision_for_test;
    use talos_workflow_job_protocol::LlmTier;

    #[test]
    fn legacy_unwired_repo_permits_extraction() {
        // No actor_repo wired in — the deployment hasn't opted into
        // tier enforcement, so don't gate.
        assert!(tier_decision_for_test(false, None));
    }

    #[test]
    fn tier2_actor_permits_extraction() {
        assert!(tier_decision_for_test(true, Some(Ok(Some(LlmTier::Tier2)))));
    }

    #[test]
    fn tier1_actor_blocks_extraction() {
        // The whole point: tier1 actors must not have data sent
        // to Anthropic. This is the security property.
        assert!(!tier_decision_for_test(
            true,
            Some(Ok(Some(LlmTier::Tier1)))
        ));
    }

    #[test]
    fn missing_actor_fails_closed() {
        assert!(!tier_decision_for_test(true, Some(Ok(None))));
    }

    #[test]
    fn db_error_fails_closed() {
        // Same fail-closed contract as
        // talos_engine::actor_binding::apply_actor_to_engine — never silently
        // promote to Tier2 on infra failure.
        assert!(!tier_decision_for_test(true, Some(Err(()))));
    }
}

#[cfg(test)]
mod batch_upsert_tests {
    use super::{
        build_unwind_upsert_cypher, group_triples_for_upsert, Entity, Triple,
        MAX_RULE_BASED_TRIPLES,
    };

    // Small constructors so the tests read like the extraction sites.
    fn ent(label: &str, name: &str) -> Entity {
        Entity {
            label: label.to_string(),
            name: name.to_string(),
            properties: vec![],
        }
    }

    fn triple(s_label: &str, s_name: &str, pred: &str, o_label: &str, o_name: &str) -> Triple {
        Triple {
            subject: ent(s_label, s_name),
            predicate: pred.to_string(),
            object: ent(o_label, o_name),
        }
    }

    #[test]
    fn empty_input_produces_no_groups() {
        assert!(group_triples_for_upsert(&[]).is_empty());
    }

    #[test]
    fn triples_with_same_label_tuple_collapse_into_one_group() {
        // The Jira shape: every triple is Ticket -ASSIGNED_TO-> Person.
        // N issues → ONE group → ONE round-trip (the whole point of the
        // fix). Each issue still contributes its own param row.
        let triples = vec![
            triple("Ticket", "PROJ-1", "ASSIGNED_TO", "Person", "alice"),
            triple("Ticket", "PROJ-2", "ASSIGNED_TO", "Person", "bob"),
            triple("Ticket", "PROJ-3", "ASSIGNED_TO", "Person", "Unassigned"),
        ];
        let groups = group_triples_for_upsert(&triples);
        assert_eq!(groups.len(), 1, "one (Ticket,Person,ASSIGNED_TO) group");
        assert_eq!(groups[0].rows.len(), 3, "one $rows entry per issue");
        // Param rows carry the per-triple names, in order.
        assert_eq!(groups[0].rows[0].subject_name, "PROJ-1");
        assert_eq!(groups[0].rows[0].object_name, "alice");
        assert_eq!(groups[0].rows[2].object_name, "Unassigned");
        // Cypher is the UNWIND form binding the names from `t`.
        assert!(groups[0].cypher.contains("UNWIND $rows AS t"));
        assert!(groups[0].cypher.contains("name: t.subject_name"));
        assert!(groups[0].cypher.contains("name: t.object_name"));
    }

    #[test]
    fn distinct_label_tuples_split_into_separate_groups_preserving_first_seen_order() {
        let triples = vec![
            triple("Ticket", "PROJ-1", "ASSIGNED_TO", "Person", "alice"),
            triple("Person", "alice", "DISCUSSED_IN", "Email", "subject-x"),
            triple("Ticket", "PROJ-2", "ASSIGNED_TO", "Person", "bob"), // back to group 0
            triple(
                "Meeting",
                "standup",
                "RELATED_TO",
                "Concept",
                "meeting_prep",
            ),
        ];
        let groups = group_triples_for_upsert(&triples);
        assert_eq!(groups.len(), 3, "three distinct (s,o,pred) tuples");
        // First-seen ordering preserved.
        assert!(groups[0].cypher.contains(":Ticket"));
        assert!(groups[0].cypher.contains(":Person"));
        assert!(groups[0].cypher.contains(":ASSIGNED_TO"));
        assert_eq!(groups[0].rows.len(), 2, "both ASSIGNED_TO triples coalesce");
        assert!(groups[1].cypher.contains(":Email"));
        assert!(groups[1].cypher.contains(":DISCUSSED_IN"));
        assert_eq!(groups[1].rows.len(), 1);
        assert!(groups[2].cypher.contains(":Meeting"));
        assert!(groups[2].cypher.contains(":Concept"));
        assert!(groups[2].cypher.contains(":RELATED_TO"));
        assert_eq!(groups[2].rows.len(), 1);
    }

    #[test]
    fn grouping_keys_on_sanitized_labels_not_raw() {
        // Two triples whose RAW labels differ only by casing /
        // unknown-ness but normalize to the SAME canonical token must
        // share a group, otherwise the group key wouldn't match the
        // emitted Cypher and we'd over-split. "ticket"/"TICKET" → Ticket;
        // a bogus subject label → Concept; "assigned_to" → ASSIGNED_TO.
        let triples = vec![
            triple("ticket", "A", "assigned_to", "person", "x"),
            triple("TICKET", "B", "ASSIGNED_TO", "Person", "y"),
        ];
        let groups = group_triples_for_upsert(&triples);
        assert_eq!(groups.len(), 1, "casing/normalization must not over-split");
        assert_eq!(groups[0].rows.len(), 2);
        // Canonical casing flows into the Cypher.
        assert!(groups[0].cypher.contains(":Ticket"));
        assert!(groups[0].cypher.contains(":Person"));
        assert!(groups[0].cypher.contains(":ASSIGNED_TO"));
    }

    #[test]
    fn cypher_uses_only_sanitized_labels_for_a_cypher_breakout_attempt() {
        // A label-injection attempt must never reach the emitted Cypher
        // verbatim — sanitize_label maps it to a safe default. Defense
        // in depth: the grouping path doesn't re-introduce the raw label.
        let triples = vec![triple(
            "Ticket) DETACH DELETE n //",
            "PROJ-1",
            "ASSIGNED_TO",
            "Person",
            "alice",
        )];
        let groups = group_triples_for_upsert(&triples);
        assert_eq!(groups.len(), 1);
        assert!(
            !groups[0].cypher.contains("DETACH DELETE"),
            "raw injection text leaked into Cypher: {}",
            groups[0].cypher
        );
        // Maps to the safe default node label.
        assert!(groups[0].cypher.contains(":Concept"));
    }

    #[test]
    fn build_unwind_upsert_cypher_matches_single_triple_merge_semantics() {
        // The batched Cypher must keep the SAME match keys
        // ({actor_id, name}) and the SAME SET-on-both-create-and-match
        // clauses as the original single-triple upsert, so the graph
        // result is identical. We pin the structural pieces.
        let c = build_unwind_upsert_cypher("Ticket", "Person", "ASSIGNED_TO");
        assert!(c.starts_with("UNWIND $rows AS t"));
        assert!(c.contains("MERGE (s:Ticket {actor_id: $actor_id, name: t.subject_name})"));
        assert!(c.contains("MERGE (o:Person {actor_id: $actor_id, name: t.object_name})"));
        assert!(c.contains("MERGE (s)-[r:ASSIGNED_TO]->(o)"));
        // SET clauses on subject, object, and relationship.
        assert_eq!(
            c.matches("source_key = $source_key, ").count(),
            3,
            "SET on s, o, and r — same as the per-triple path"
        );
        assert!(c.contains("s.updated_at = $now"));
        assert!(c.contains("o.updated_at = $now"));
        assert!(c.contains("r.updated_at = $now"));
        // Bound property maps applied to the nodes (not the relationship).
        assert!(c.contains("SET s += t.subject_props"));
        assert!(c.contains("SET o += t.object_props"));
        // Property SET must precede the provenance SET so source_key /
        // updated_at always win on a key collision (defense in depth).
        let s_props = c.find("SET s += t.subject_props").unwrap();
        let s_prov = c.find("SET s.source_key").unwrap();
        assert!(
            s_props < s_prov,
            "props SET must come before provenance SET"
        );
    }

    #[test]
    fn group_triples_threads_entity_properties_into_rows_raw() {
        // The grouping transform carries properties through verbatim;
        // sanitization happens later at BoltMap-build time. Here we pin
        // that the (raw) pairs survive grouping in row order.
        let mut subj = ent("Ticket", "PROJ-1");
        subj.properties = vec![
            ("summary".to_string(), "ship the thing".to_string()),
            ("status".to_string(), "In Progress".to_string()),
        ];
        let triples = vec![Triple {
            subject: subj,
            predicate: "ASSIGNED_TO".to_string(),
            object: ent("Person", "alice"),
        }];
        let groups = group_triples_for_upsert(&triples);
        assert_eq!(groups[0].rows[0].subject_props.len(), 2);
        assert_eq!(groups[0].rows[0].subject_props[0].0, "summary");
        assert!(
            groups[0].rows[0].object_props.is_empty(),
            "object had no properties"
        );
    }

    #[test]
    // Deliberate constant assertions — a guard test that fails loudly
    // if someone edits the cap outside its sane range.
    #[allow(clippy::assertions_on_constants)]
    fn rule_based_cap_constant_is_a_sane_bound() {
        // The cap exists to stop an unbounded Jira sync from emitting
        // unbounded MERGE work. It must be > the LLM path's 20 (a real
        // sync can carry more than 20 tickets) but bounded.
        assert!(MAX_RULE_BASED_TRIPLES > 20);
        assert!(MAX_RULE_BASED_TRIPLES <= 1000);
    }
}

#[cfg(test)]
mod property_sanitization_tests {
    use super::{
        sanitize_property_key, sanitized_property_pairs, MAX_PROPERTIES_PER_NODE,
        MAX_PROPERTY_KEY_LEN, MAX_PROPERTY_VALUE_LEN,
    };

    // `sanitize_property_key` is the guard between user/LLM-derived entity
    // property keys and the `SET n += $props` map. The map is a bound
    // parameter, so a key can't break out into Cypher — but it CAN clobber
    // a structural property (tenant `actor_id`, MERGE `name`, provenance)
    // if not filtered. These pin both layers: charset normalization and
    // reserved-key rejection.

    #[test]
    fn reserved_structural_keys_are_dropped_case_insensitively() {
        // The whole point: a property literally named actor_id must NOT be
        // settable — it would move the node into another tenant's subgraph.
        for raw in [
            "actor_id",
            "ACTOR_ID",
            "Actor_Id",
            "name",
            "NAME",
            "source_key",
            "updated_at",
            // charset-normalization must not let a spaced variant sneak the
            // exact reserved token past the filter.
            " actor_id ",
            "actor_id\n",
        ] {
            assert_eq!(
                sanitize_property_key(raw),
                None,
                "reserved key {raw:?} must be dropped"
            );
        }

        // Sibling keys that normalize to a DIFFERENT token are NOT reserved
        // — `actorid`/`actorId` are distinct property names from the
        // structural `actor_id` and are safe to persist.
        assert_eq!(
            sanitize_property_key("actor-id"),
            Some("actorid".to_string())
        );
        assert_eq!(
            sanitize_property_key("actorId"),
            Some("actorId".to_string())
        );
    }

    #[test]
    fn cypher_breakout_keys_are_neutralized_or_dropped() {
        // Even though keys are bound (not interpolated), the charset filter
        // is defense in depth: nothing Cypher-significant survives.
        for raw in [
            "summary`) DETACH DELETE n //",
            "foo} SET n.actor_id =",
            "a:b;DROP",
            "key with spaces",
        ] {
            if let Some(k) = sanitize_property_key(raw) {
                assert!(
                    k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                    "sanitized key {k:?} leaked a Cypher-significant char"
                );
            }
        }
    }

    #[test]
    fn empty_all_punctuation_and_leading_digit_keys_are_dropped() {
        assert_eq!(sanitize_property_key(""), None);
        assert_eq!(sanitize_property_key("   "), None);
        assert_eq!(sanitize_property_key("!@#$%"), None);
        // Leading digit → dropped (Neo4j identifier shape, also bars all-digit).
        assert_eq!(sanitize_property_key("1foo"), None);
        assert_eq!(sanitize_property_key("123"), None);
    }

    #[test]
    fn valid_keys_pass_through_normalized() {
        assert_eq!(
            sanitize_property_key("summary"),
            Some("summary".to_string())
        );
        assert_eq!(sanitize_property_key("status"), Some("status".to_string()));
        assert_eq!(
            sanitize_property_key("_internal"),
            Some("_internal".to_string())
        );
        // Punctuation stripped, alphanumerics kept.
        assert_eq!(
            sanitize_property_key("due-date!"),
            Some("duedate".to_string())
        );
    }

    #[test]
    fn over_length_keys_are_dropped() {
        let long = "a".repeat(MAX_PROPERTY_KEY_LEN + 1);
        assert_eq!(sanitize_property_key(&long), None);
        let ok = "a".repeat(MAX_PROPERTY_KEY_LEN);
        assert_eq!(sanitize_property_key(&ok), Some(ok));
    }

    #[test]
    fn pairs_apply_value_cap_count_cap_and_last_writer_wins() {
        // Value-length cap.
        let huge_val = "x".repeat(MAX_PROPERTY_VALUE_LEN + 50);
        let pairs = sanitized_property_pairs(&[("k".to_string(), huge_val)]);
        assert_eq!(pairs[0].1.chars().count(), MAX_PROPERTY_VALUE_LEN);

        // Per-node count cap: emit more distinct keys than allowed.
        let many: Vec<(String, String)> = (0..(MAX_PROPERTIES_PER_NODE + 5))
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        let pairs = sanitized_property_pairs(&many);
        assert_eq!(pairs.len(), MAX_PROPERTIES_PER_NODE);

        // Last-writer-wins on keys that normalize to the same token, and
        // a dropped reserved key in the middle doesn't consume a slot.
        let pairs = sanitized_property_pairs(&[
            ("status".to_string(), "old".to_string()),
            ("actor_id".to_string(), "evil-tenant".to_string()), // dropped
            ("status".to_string(), "new".to_string()),
        ]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("status".to_string(), "new".to_string()));
    }

    #[test]
    fn reserved_key_never_survives_into_persisted_pairs() {
        let pairs = sanitized_property_pairs(&[
            ("actor_id".to_string(), "attacker".to_string()),
            ("name".to_string(), "spoof".to_string()),
            ("source_key".to_string(), "x".to_string()),
            ("updated_at".to_string(), "y".to_string()),
            ("category".to_string(), "real".to_string()),
        ]);
        assert_eq!(pairs, vec![("category".to_string(), "real".to_string())]);
    }
}

// Pure tests for the rule-based extraction cap. `extract_triples_rule_based`
// is a `&self` method but touches no async state for the Jira shape, so we
// exercise it through a test-only constructor that never connects to Neo4j.
#[cfg(test)]
mod rule_based_cap_tests {
    use super::{GraphRagService, MAX_RULE_BASED_TRIPLES};

    // Build a service whose Neo4j handle is never used — the rule-based
    // extractor is pure over its inputs. We construct the `Arc<Graph>`
    // lazily via a connection-config that is never driven (no `.run()` in
    // these tests), so no live database is required.
    fn jira_value_with_n_issues(n: usize) -> serde_json::Value {
        let issues: Vec<serde_json::Value> = (0..n)
            .map(|i| {
                serde_json::json!({
                    "key": format!("PROJ-{i}"),
                    "summary": "do the thing",
                    "assignee": "alice",
                    "status": "In Progress",
                })
            })
            .collect();
        serde_json::json!({ "data": { "issues": issues } })
    }

    #[tokio::test]
    async fn jira_sync_is_capped_at_max_rule_based_triples() {
        // A `Graph` we never call `.run()` on. `connect` is lazy enough
        // for `neo4rs` 0.8 that constructing it doesn't dial the server;
        // even if it did, the extractor under test never touches it.
        let svc = GraphRagService::test_stub_without_neo4j().await;

        // 5x the cap of Jira issues → without the cap this would be 5x
        // the cap of triples (one ASSIGNED_TO per issue).
        let value = jira_value_with_n_issues(MAX_RULE_BASED_TRIPLES * 5);
        let triples = svc.extract_triples_rule_based("jira_work_context", &value);
        assert_eq!(
            triples.len(),
            MAX_RULE_BASED_TRIPLES,
            "rule-based Jira path must be bounded by the cap"
        );
    }

    #[tokio::test]
    async fn small_jira_sync_is_not_truncated() {
        let svc = GraphRagService::test_stub_without_neo4j().await;
        let value = jira_value_with_n_issues(7);
        let triples = svc.extract_triples_rule_based("jira_work_context", &value);
        assert_eq!(triples.len(), 7, "under-cap syncs are untouched");
    }
}
