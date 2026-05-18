-- Add vector embedding column to actor_memory for semantic similarity search.
-- The embedding is optional (NULL = not yet embedded). Rows without an embedding
-- fall back to keyword search in actor_recall_semantic.
--
-- Dimension matches EMBEDDING_DIMENSIONS env default (1536 for text-embedding-3-small).
-- If you use a different model, change the dimension here and reindex.
ALTER TABLE actor_memory
    ADD COLUMN IF NOT EXISTS embedding vector(1536);

-- IVFFlat index for approximate nearest-neighbour search.
-- probes=10 is the default scan breadth; raise for higher recall at the cost of speed.
-- Only indexes rows that have an embedding (WHERE embedding IS NOT NULL).
CREATE INDEX IF NOT EXISTS idx_actor_memory_embedding
    ON actor_memory USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20)
    WHERE embedding IS NOT NULL;
