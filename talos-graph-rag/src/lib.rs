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
    pub fn with_secrets(
        mut self,
        secrets: Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
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
    /// `ActorRepository::apply_actor_to_engine`.
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
            // contract as `ActorRepository::apply_actor_to_engine`.
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
        for triple in triples {
            self.upsert_triple(actor_id, memory_key, &triple).await?;
        }

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
    ///     `ActorRepository::apply_actor_to_engine`.
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
    async fn resolve_anthropic_key(
        &self,
    ) -> Option<talos_secrets_manager::Zeroizing<String>> {
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

        let response: serde_json::Value = resp.json().await?;
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

    /// Upsert a single triple into Neo4j.
    async fn upsert_triple(&self, actor_id: Uuid, source_key: &str, triple: &Triple) -> Result<()> {
        let actor_str = actor_id.to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // MERGE both nodes (create if not exists, update if exists).
        // Then MERGE the relationship.
        let cypher = format!(
            "MERGE (s:{} {{actor_id: $actor_id, name: $subject_name}}) \
             SET s.source_key = $source_key, s.updated_at = $now \
             MERGE (o:{} {{actor_id: $actor_id, name: $object_name}}) \
             SET o.source_key = $source_key, o.updated_at = $now \
             MERGE (s)-[r:{}]->(o) \
             SET r.source_key = $source_key, r.updated_at = $now",
            sanitize_label(&triple.subject.label),
            sanitize_label(&triple.object.label),
            sanitize_label(&triple.predicate),
        );

        // Set additional properties on subject node.
        let q = neo4rs::query(&cypher)
            .param("actor_id", actor_str.as_str())
            .param("subject_name", triple.subject.name.as_str())
            .param("object_name", triple.object.name.as_str())
            .param("source_key", source_key)
            .param("now", now.as_str());

        self.graph.run(q).await.context("Neo4j upsert failed")?;
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

/// An entity node in the knowledge graph.
#[derive(Debug, Clone)]
struct Entity {
    label: String,
    name: String,
    // MCP-953 (2026-05-15): Properties are populated at extract time
    // (e.g. Ticket.summary/status, Email.category — see `triples.push`
    // sites in `extract_triples`) but `upsert_triple` does NOT
    // currently propagate them into the Neo4j MERGE — the cypher only
    // sets `source_key` and `updated_at`. Field is real data that gets
    // dropped on persist. Wiring `properties` through to a SET clause
    // (per the misleading "Set additional properties on subject node"
    // comment at the upsert site) is non-trivial because property keys
    // are user-derived and need sanitisation against Cypher injection.
    // Tracking as deferred fix; field kept so the call sites stay
    // ready for that follow-up.
    #[allow(dead_code)]
    properties: Vec<(String, String)>,
}

/// A subject-predicate-object triple.
#[derive(Debug, Clone)]
struct Triple {
    subject: Entity,
    predicate: String,
    object: Entity,
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
        assert!(tier_decision_for_test(
            true,
            Some(Ok(Some(LlmTier::Tier2)))
        ));
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
        // ActorRepository::apply_actor_to_engine — never silently
        // promote to Tier2 on infra failure.
        assert!(!tier_decision_for_test(true, Some(Err(()))));
    }
}
