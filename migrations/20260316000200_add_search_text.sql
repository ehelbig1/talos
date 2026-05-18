ALTER TABLE workflows ADD COLUMN IF NOT EXISTS search_text TEXT;
CREATE INDEX IF NOT EXISTS idx_workflows_search_text_trgm ON workflows USING gin(search_text gin_trgm_ops);
