-- Agent memory: persistent key-value store with optional vector embeddings.
-- Scoped per-workflow so agents within the same workflow share memory.
-- Supports pgvector for semantic similarity search when the extension is available.

-- Enable pgvector extension (no-op if already enabled, fails gracefully if unavailable)
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgvector extension not available — vector search will be disabled';
END $$;

CREATE TABLE IF NOT EXISTS agent_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL,
    user_id UUID NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(workflow_id, key)
);

CREATE INDEX IF NOT EXISTS idx_agent_memory_workflow ON agent_memory(workflow_id);
CREATE INDEX IF NOT EXISTS idx_agent_memory_workflow_key ON agent_memory(workflow_id, key);
CREATE INDEX IF NOT EXISTS idx_agent_memory_user ON agent_memory(user_id);

-- Add embedding column and HNSW index only if pgvector is available
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
        ALTER TABLE agent_memory ADD COLUMN IF NOT EXISTS embedding vector(1536);
        CREATE INDEX IF NOT EXISTS idx_agent_memory_embedding ON agent_memory
            USING hnsw (embedding vector_cosine_ops)
            WITH (m = 16, ef_construction = 64);
    ELSE
        RAISE NOTICE 'Skipping embedding column and HNSW index — pgvector not available';
    END IF;
END $$;
