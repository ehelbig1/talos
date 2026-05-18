CREATE TABLE IF NOT EXISTS module_update_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id UUID NOT NULL,
    user_id UUID NOT NULL,
    previous_hash TEXT,
    new_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_module_history_module ON module_update_history(module_id, created_at DESC);
