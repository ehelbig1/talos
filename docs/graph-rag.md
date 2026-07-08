# Graph-RAG: the actor knowledge graph

Every actor-memory write feeds a per-actor knowledge graph in Neo4j:
`(subject) -[predicate]-> (object)` triples extracted from the memory value
(e.g. `(Alice:Person) -[WORKS_ON]-> (Talos:Project)`). The graph powers
`graph_query` / `graph_entity_context` relationship lookups and enriches
`__actor_context__` injection with entity-aware relevance.

## Extraction pipeline (write time)

1. **Rule-based first** — known memory shapes (Jira syncs, email triage,
   meeting preps) are parsed structurally: free, fast, no LLM. Capped per
   write; over-cap syncs log a WARN.
2. **LLM fallback** — unknown shapes go to an LLM with a triple-extraction
   prompt. Backend selection (`talos-graph-rag/src/lib.rs::extract_triples_llm`):
   - **Anthropic** when `anthropic/api_key` resolves (vault-first, env
     fallback) — forced tool-use, best quality.
   - **Local Ollama** otherwise, when wired (`OLLAMA_URL` +
     `TALOS_GRAPH_RAG_MODEL`) — OpenAI-compatible chat endpoint with a
     JSON-mode prompt. This is what populates the graph on Ollama-only /
     self-hosted deployments.
   - **Skip** when neither is available (one WARN per boot, then counted).
3. **Batched Neo4j upsert** — triples MERGE idempotently, grouped per
   `(subject_label, object_label, predicate)`; labels and predicates are
   sanitized against a fixed vocabulary before touching Cypher structure.

Extraction is best-effort and runs OFF the write path (detached task behind a
small semaphore): a failed or skipped extraction never fails the memory write.

## Choosing the extraction model

`TALOS_GRAPH_RAG_MODEL` names the Ollama model used for local extraction.
**Model quality matters here**: extraction requires reliable structured-JSON
output, and 1B-class models (the in-stack `talos-ollama` ships `llama3.2:1b`)
are flaky at it — expect sparse or empty graphs plus per-write parse warnings.
Recommendation:

| Deployment | Model | Notes |
|---|---|---|
| Homelab / dev with a real GPU or M-series host | `qwen2.5:7b` (or `qwen2.5-coder:7b`) | Reliable JSON, good entity recall — the verified reference config |
| In-stack `talos-ollama` only | `llama3.2:1b` (default) | Works for the wire; graph will be sparse. Pull a 7B-class model if you care about the graph |
| Anthropic key configured | (unused for tier2) | External extraction preferred automatically |

After changing the model: `ollama pull <model>`, restart the controller, and
run `graph_backfill` (below) to re-extract existing memories.

## Tier gate (data-egress invariant)

Actors carry a `max_llm_tier` ceiling. For graph extraction:

- **tier2** (default): any configured backend — Anthropic preferred, Ollama
  fallback.
- **tier1** ("data must not leave host"): extraction is **skipped entirely**
  by default. The platform cannot verify where `OLLAMA_URL` points, so it
  refuses to assume the local backend is actually local.
- Missing actor row or tier-lookup error: skipped (fail-closed).

### Tier1 local-extraction attestation

Operators who KNOW their Ollama endpoint is on-host can set
`TALOS_GRAPH_RAG_TIER1_LOCAL_OK=1` (controller env). This is a deployment-level
attestation — the same trust granularity as configuring `OLLAMA_URL` itself —
that unlocks tier1 graph extraction with strict semantics:

- Tier1 memories go to the **local Ollama backend only** — Anthropic is never
  consulted for them, even when a key is present.
- Missing-actor / lookup-error writes still skip (the attestation vouches for
  backend locality, not for unattributable writes).
- Boot logs an INFO line when active; `graph_stats` reports it as
  `tier1_local_extraction`.

Accepted values: `1`/`true`/`yes` (case-insensitive). Anything else is treated
as OFF with a WARN.

## Backfilling existing memories

Extraction fires at write time only — memories written before an extraction
backend existed (or during an outage) stay graph-less until backfilled:

```
graph_backfill(actor_id: "...", limit: 50, memory_type: "episodic")
```

Runs as a background task (one LLM call per memory); the response returns the
queued count immediately. One backfill per actor at a time; batches cap at 200
per call — re-invoke for more (re-processing is idempotent, MERGE converges).
The tier gate applies exactly as at write time.

## Diagnosing an empty graph

`graph_stats(actor_id: ...)` answers it directly:

- `extraction_backend: "none"` → no LLM backend configured. Set
  `anthropic/api_key` or wire `OLLAMA_URL` + `TALOS_GRAPH_RAG_MODEL`.
- `extraction_metrics.skipped_tier_gate` climbing → the actor is tier1 (or
  tier lookups are failing). See the attestation above.
- `extraction_metrics.llm_failures` climbing → backend erroring: model not
  pulled, `OLLAMA_URL` unreachable, revoked Anthropic key, or the model emits
  unparseable JSON (try a larger model).
- Counters healthy but `total_nodes: 0` → memories predate the backend; run
  `graph_backfill`.
- `extraction_metrics` is since-boot and process-wide (deployment-level, not
  per-actor).
