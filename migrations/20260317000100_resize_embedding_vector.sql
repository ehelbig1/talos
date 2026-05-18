-- Resize workflow embedding column from vector(1536) to vector(768).
--
-- Background: the default embedding provider is now Ollama with nomic-embed-text,
-- which produces 768-dimensional vectors (not 1536). PostgreSQL pgvector enforces
-- dimension consistency at INSERT time, so the column must match the model output.
--
-- Effect: all existing embeddings are dropped. After applying this migration, run
-- the MCP tool `generate_workflow_embeddings` to re-embed using the configured model.
--
-- To use a different model (e.g. text-embedding-3-small → 1536 dims), set
-- EMBEDDING_DIMENSIONS in your environment and create a follow-up migration.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workflows' AND column_name = 'embedding'
    ) THEN
        -- Drop the old IVFFLAT index before altering the column type.
        DROP INDEX IF EXISTS idx_workflows_embedding;

        -- Drop and recreate the column at the new dimension.
        -- (pgvector does not support ALTER COLUMN TYPE for vector columns.)
        ALTER TABLE workflows DROP COLUMN embedding;
        ALTER TABLE workflows ADD COLUMN embedding vector(768);

        CREATE INDEX IF NOT EXISTS idx_workflows_embedding
            ON workflows USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);

        RAISE NOTICE 'workflows.embedding resized to vector(768). Re-embed via generate_workflow_embeddings.';
    ELSE
        -- Column absent — create fresh at 768 dimensions.
        CREATE EXTENSION IF NOT EXISTS vector;
        ALTER TABLE workflows ADD COLUMN IF NOT EXISTS embedding vector(768);

        CREATE INDEX IF NOT EXISTS idx_workflows_embedding
            ON workflows USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);

        RAISE NOTICE 'workflows.embedding created at vector(768).';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not resize embedding column: % — pgvector may not be available', SQLERRM;
END $$;
