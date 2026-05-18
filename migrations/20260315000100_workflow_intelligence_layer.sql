-- Workflow Intelligence Layer: semantic search, capabilities, intent, reuse tracking

-- 1. Capability tags (structured taxonomy, separate from free-form tags)
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS capabilities TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_workflows_capabilities ON workflows USING GIN(capabilities);

-- 2. Intent registration (structured JSON for machine-readable workflow purpose)
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS intent JSONB;

-- 3. Readiness score (computed, cached for performance)
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS readiness_score INTEGER;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS readiness_computed_at TIMESTAMPTZ;

-- 4. Semantic embeddings via pgvector (if extension available)
-- Note: pgvector must be installed separately. The embedding column is added
-- conditionally to avoid blocking the migration if pgvector isn't available.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
    ALTER TABLE workflows ADD COLUMN IF NOT EXISTS embedding vector(1536);
    CREATE INDEX IF NOT EXISTS idx_workflows_embedding ON workflows USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgvector not available — semantic search will use keyword fallback';
END $$;

-- 5. Reuse tracking
CREATE TABLE IF NOT EXISTS workflow_reuse_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    caller_session TEXT,
    invocation_type TEXT NOT NULL DEFAULT 'trigger', -- trigger, call, replay, test
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reuse_events_workflow ON workflow_reuse_events(workflow_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reuse_events_created ON workflow_reuse_events(created_at DESC);
