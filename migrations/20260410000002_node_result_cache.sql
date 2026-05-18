-- Content-addressable node result cache for deterministic modules.
-- Cache key = SHA-256(module_content_hash || canonical_input_json).
-- Only minimal-node modules are cached (no side effects).

CREATE TABLE IF NOT EXISTS node_result_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key TEXT NOT NULL UNIQUE,
    module_hash TEXT NOT NULL,
    module_version TEXT NOT NULL DEFAULT '1.0.0',
    input_hash TEXT NOT NULL,
    output_json JSONB NOT NULL,
    fuel_consumed BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_hit_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hit_count BIGINT NOT NULL DEFAULT 0,
    -- Auto-expire stale cache entries (default 7 days)
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days'
);

CREATE INDEX IF NOT EXISTS idx_node_result_cache_key ON node_result_cache (cache_key);
-- Regular B-tree index for cleanup queries (DELETE WHERE expires_at < NOW()).
-- Cannot use a partial index with NOW() because it is not IMMUTABLE.
CREATE INDEX IF NOT EXISTS idx_node_result_cache_expires ON node_result_cache (expires_at);

COMMENT ON TABLE node_result_cache IS 'Content-addressable cache for deterministic WASM module outputs. Keyed on (module_hash, input_hash). Only populated for minimal-node capability world.';
