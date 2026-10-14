# A bookkeeping memory write costs nothing it does not need (2026-10-14)

A step counter written by a module (`work/log/<ticket>/<step>`, about 110
bytes of numbers, one write per step a person takes) was embedded and, because
its `metadata.kind` is not on `SYNTHETIC_MEMORY_KINDS`, queued for entity
extraction by the local model on every write. The rows could also surface in
semantic recall.

## Found: the write the brief asks for already exists

The brief proposed `__memory_write__.index: false`. The platform already has
that write: **`memory_type: "scratchpad"`**. Nothing told a module author so.
In `talos_memory::persist_memory_with_metadata_typed` and the transactional
sibling, a scratchpad row is:

* **not embedded** (`canonical_type != "scratchpad"` gates the embedding call);
* **not sent for graph extraction** (the same gate on `spawn_graph_extraction`);
* **not backfilled** (both `backfill_embeddings` selects skip
  `memory_type = 'scratchpad'`);
* **not in `__actor_context__`** (the recency and semantic layers drop it,
  `docs/smart-actor-context.md`);
* **durable for as long as asked:** its 24-hour default applies only when
  `ttl_hours` is absent, and an explicit `ttl_hours` is honoured up to the
  ten-year ceiling;
* **read by key** like any other row (`get`, `get_entry`, `list_keys`,
  `actor_recall`).

`actor_remember` already takes `memory_type: "scratchpad"` and `ttl_hours`,
and its description and `docs/memory-reflection.md` call scratchpad
"ephemeral bookkeeping". So the brief's suggested field would be a second way
to say the same thing, and it is not added (instructions: an item that is
already possible is said to be so, not re-invented).

**One gap was real: semantic recall's keyword fallback.** The vector path
never returns a scratchpad row (it has no embedding). But when the vector path
came back empty, `recall_semantic_filtered` fell back to a key match over rows
it "could not judge" (`embedding IS NULL`), and every scratchpad row is one of
those. A query whose words appear in a tally's key returned the tally. That is
the brief's "the rows can surface in semantic recall".

## Decided

* **Semantic recall's fallback excludes `scratchpad`**
  (`recall_keyword_inner(.., semantic_fallback: true)`). An explicit keyword
  search (`recall_keyword`, `actor_recall`'s keyword mode) still finds such a
  row: it is kept out of SEMANTIC recall, not hidden.
* **`CLAUDE.md`'s `__memory_write__` list says it**: a bookkeeping write is
  `"scratchpad"` with an explicit `ttl_hours`, and there is no "unindexed"
  flag beside it.

## Measured (dev stack, made-up 111-byte tally value)

| | before (episodic / semantic write) | after (`scratchpad`) |
|---|---|---|
| Embedding, host Ollama `mxbai-embed-large` (the live controller's `EMBEDDING_MODEL`), 1024 dims | 81 ms on the first call (model load), then p50 17 ms, p90 19 ms, max 21 ms over 20 calls | none |
| Entity extraction, host Ollama `qwen2.5-coder:7b` (the live `TALOS_GRAPH_RAG_MODEL`), the extractor's system contract, `num_predict` 2000 | 4.5 s cold, 0.6 to 0.7 s warm; the tally matches no rule-based shape, so every write goes to the model | none |
| Graph | 2 of 3 runs invented a relationship from the counter (the ticket "CREATED" by "owner") | nothing written |

The extraction runs on the same local model queue as the workflows' own local
LLM calls, so its cost lands on them too.

## Tests

`controller/tests/scratchpad_bookkeeping_tests.rs` (migrated clone, one test
function). A `__memory_write__` goes through the engine's real
`ControllerNodeHook`, against the counting embedding stand-in
(`talos-memory/tests/embedding_mock`, included by path rather than copied) and
a counting graph hook:

* an ordinary write makes one embedding call and one extraction;
* a scratchpad write with `ttl_hours: 8760` makes none, has a NULL embedding,
  is readable by key, and expires in a year;
* it is absent from `recall_semantic_filtered` on the keyword-fallback path,
  present in `recall_keyword`; the ordinary row is still found semantically.

**Reproduced and mutation-checked as one:** with the fallback flag set back to
`false` (the old behaviour), the test fails with "a bookkeeping row came back
from semantic recall (keyword_fallback)". Restored and touched, green.

## Deliberately NOT done

* `__memory_write__.index` and an `actor_remember` twin (see above).
* A host-call route: `agent_memory::set` always writes `episodic` with the
  long KV TTL, so a module that keeps a tally through host calls is still
  embedded. A module that needs a cheap counter writes it through the
  envelope. A `set` that takes a memory type would be a WIT change.
* Changing `scratchpad`'s 24-hour default.
