-- Resize embedding columns from vector(768) to vector(1024) for Voyage AI
-- (voyage-3 / voyage-3-large / voyage-code-3 / voyage-multilingual-2 family).
--
-- Background: prior config defaulted to nomic-embed-text via Ollama (768-dim)
-- but the chart never shipped an Ollama deployment template, so embedding
-- coverage stayed at 0. Switching to Voyage as the hosted provider; their
-- general-purpose models emit 1024-dim vectors. pgvector enforces dimension
-- consistency at INSERT time so the column shape must match.
--
-- Effect: all existing embeddings are wiped (column was 0% populated in prod
-- per session_start coverage gauge). After applying, set:
--   EMBEDDING_API_URL=https://api.voyageai.com/v1/embeddings
--   EMBEDDING_API_KEY=<voyage-key>
--   EMBEDDING_MODEL=voyage-3
--   EMBEDDING_DIMENSIONS=1024
-- Next session_start auto-heals workflows; actor_memory back-fills lazily on
-- next persist + via consolidate_actor_memory; semantic_execution_cache
-- entries re-embed on next workflow execution.
--
-- The legacy `agent_memory` table (vector(1536), unused — zero live SQL refs
-- in controller) is intentionally NOT touched. Drop it in a follow-up cleanup
-- migration if desired.

-- workflows.embedding ────────────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_workflows_embedding;

ALTER TABLE workflows
    ALTER COLUMN embedding TYPE vector(1024)
    USING NULL;

CREATE INDEX idx_workflows_embedding
    ON workflows USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 20);

-- actor_memory.embedding ────────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_actor_memory_embedding;

ALTER TABLE actor_memory
    ALTER COLUMN embedding TYPE vector(1024)
    USING NULL;

CREATE INDEX idx_actor_memory_embedding
    ON actor_memory USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

-- semantic_execution_cache.input_embedding ──────────────────────────────────
DROP INDEX IF EXISTS idx_semantic_cache_embedding;

ALTER TABLE semantic_execution_cache
    ALTER COLUMN input_embedding TYPE vector(1024)
    USING NULL;

CREATE INDEX idx_semantic_cache_embedding
    ON semantic_execution_cache USING ivfflat (input_embedding vector_cosine_ops)
    WITH (lists = 10);
