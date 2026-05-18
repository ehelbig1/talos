-- Fix actor_memory embedding column dimension to match the configured model.
--
-- The column was created as vector(1536) (OpenAI text-embedding-3-small default)
-- but the platform is configured with nomic-embed-text via Ollama which produces
-- 768-dimensional vectors. The generate_embedding function checks dimensions and
-- returns None on mismatch, which is why all existing memories have NULL embeddings.
--
-- This migration:
-- 1. Drops the IVFFlat index (can't alter vector dimension with index present)
-- 2. Alters the column to vector(768)
-- 3. Recreates the index

DROP INDEX IF EXISTS idx_actor_memory_embedding;

ALTER TABLE actor_memory
    ALTER COLUMN embedding TYPE vector(768)
    USING NULL;

CREATE INDEX idx_actor_memory_embedding
    ON actor_memory USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);
