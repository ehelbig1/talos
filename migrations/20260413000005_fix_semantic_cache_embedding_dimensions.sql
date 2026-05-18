-- Fix semantic_execution_cache.input_embedding dimension to match the
-- configured embedding model (nomic-embed-text, 768-dim). The original
-- migration created it as vector(1536) (OpenAI default).

DROP INDEX IF EXISTS idx_semantic_cache_embedding;

ALTER TABLE semantic_execution_cache
    ALTER COLUMN input_embedding TYPE vector(768)
    USING NULL;

CREATE INDEX idx_semantic_cache_embedding
    ON semantic_execution_cache USING ivfflat (input_embedding vector_cosine_ops)
    WITH (lists = 10);
